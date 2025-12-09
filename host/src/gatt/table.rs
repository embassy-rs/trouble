/// A table of attributes.
pub struct AttributeTable<'d, M: RawMutex, const MAX: usize> {
    inner: Mutex<M, RefCell<InnerTable<'d, MAX>>>,
    handle: u16,
}

pub(crate) struct InnerTable<'d, const MAX: usize> {
    attributes: Vec<Attribute<'d>, MAX>,
}

impl<'d, const MAX: usize> InnerTable<'d, MAX> {
    fn push(&mut self, attribute: Attribute<'d>) {
        self.attributes.push(attribute).unwrap();
    }
}

impl<M: RawMutex, const MAX: usize> Default for AttributeTable<'_, M, MAX> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'d, M: RawMutex, const MAX: usize> AttributeTable<'d, M, MAX> {
    /// Create a new GATT table.
    pub fn new() -> Self {
        Self {
            handle: 1,
            inner: Mutex::new(RefCell::new(InnerTable { attributes: Vec::new() })),
        }
    }

    pub(crate) fn with_inner<F: Fn(&mut InnerTable<'d, MAX>)>(&self, f: F) {
        self.inner.lock(|inner| {
            let mut table = inner.borrow_mut();
            f(&mut table);
        })
    }

    pub(crate) fn iterate<F: FnMut(AttributeIterator<'_, 'd>) -> R, R>(&self, mut f: F) -> R {
        self.inner.lock(|inner| {
            let mut table = inner.borrow_mut();
            let it = AttributeIterator {
                attributes: &mut table.attributes[..],
                pos: 0,
            };
            f(it)
        })
    }

    fn push(&mut self, mut attribute: Attribute<'d>) -> u16 {
        let handle = self.handle;
        attribute.handle = handle;
        self.inner.lock(|inner| {
            let mut inner = inner.borrow_mut();
            inner.push(attribute);
        });
        self.handle += 1;
        handle
    }

    /// Add a service to the attribute table (group of characteristics)
    pub fn add_service(&mut self, service: Service) -> ServiceBuilder<'_, 'd, M, MAX> {
        let len = self.inner.lock(|i| i.borrow().attributes.len());
        let handle = self.handle;
        self.push(Attribute {
            uuid: PRIMARY_SERVICE.into(),
            handle: 0,
            last_handle_in_group: 0,
            data: AttributeData::Service { uuid: service.uuid },
        });
        ServiceBuilder {
            handle,
            start: len,
            table: self,
        }
    }

    pub(crate) fn set_raw(&self, attribute: u16, input: &[u8]) -> Result<(), Error> {
        self.iterate(|mut it| {
            while let Some(att) = it.next() {
                if att.handle == attribute {
                    if let AttributeData::Data {
                        props: _,
                        value,
                        variable_len,
                        len,
                    } = &mut att.data
                    {
                        let expected_len = value.len();
                        let actual_len = input.len();

                        if expected_len == actual_len {
                            value.copy_from_slice(input);
                            return Ok(());
                        } else if *variable_len && actual_len <= expected_len {
                            value[..input.len()].copy_from_slice(input);
                            *len = input.len() as u16;
                            return Ok(());
                        } else {
                            return Err(Error::UnexpectedDataLength {
                                expected: expected_len,
                                actual: actual_len,
                            });
                        }
                    }
                }
            }
            Err(Error::NotFound)
        })
    }

    /// Set the value of a characteristic
    ///
    /// The provided data must exactly match the size of the storage for the characteristic,
    /// otherwise this function will panic.
    ///
    /// If the characteristic for the handle cannot be found, or the shape of the data does not match the type of the characterstic,
    /// an error is returned
    pub fn set<T: AttributeHandle>(&self, attribute_handle: &T, input: &T::Value) -> Result<(), Error> {
        let gatt_value = input.as_gatt();
        self.set_raw(attribute_handle.handle(), gatt_value)
    }

    /// Read the value of the characteristic and pass the value to the provided closure.
    ///
    /// The return value of the closure is returned in this function and is assumed to be infallible.
    ///
    /// If the characteristic for the handle cannot be found, an error is returned.
    pub fn get<T: AttributeHandle<Value = V>, V: FromGatt>(&self, attribute_handle: &T) -> Result<T::Value, Error> {
        self.iterate(|mut it| {
            while let Some(att) = it.next() {
                if att.handle == attribute_handle.handle() {
                    if let AttributeData::Data {
                        props,
                        value,
                        variable_len,
                        len,
                    } = &mut att.data
                    {
                        let value_slice = if *variable_len { &value[..*len as usize] } else { value };

                        match T::Value::from_gatt(value_slice) {
                            Ok(v) => return Ok(v),
                            Err(_) => {
                                let mut invalid_data = [0u8; MAX_INVALID_DATA_LEN];
                                let len_to_copy = value_slice.len().min(MAX_INVALID_DATA_LEN);
                                invalid_data[..len_to_copy].copy_from_slice(&value_slice[..len_to_copy]);

                                return Err(Error::CannotConstructGattValue(invalid_data));
                            }
                        }
                    }
                }
            }
            Err(Error::NotFound)
        })
    }

    /// Return the characteristic which corresponds to the supplied value handle
    ///
    /// If no characteristic corresponding to the given value handle was found, returns an error
    pub fn find_characteristic_by_value_handle<T: AsGatt>(&self, handle: u16) -> Result<Characteristic<T>, Error> {
        self.iterate(|mut it| {
            while let Some(att) = it.next() {
                if att.handle == handle {
                    // If next is CCCD
                    if let Some(next) = it.next() {
                        if let AttributeData::Cccd {
                            notifications: _,
                            indications: _,
                        } = &next.data
                        {
                            return Ok(Characteristic {
                                handle,
                                cccd_handle: Some(next.handle),
                                phantom: PhantomData,
                            });
                        } else {
                            return Ok(Characteristic {
                                handle,
                                cccd_handle: None,
                                phantom: PhantomData,
                            });
                        }
                    } else {
                        return Ok(Characteristic {
                            handle,
                            cccd_handle: None,
                            phantom: PhantomData,
                        });
                    }
                }
            }
            Err(Error::NotFound)
        })
    }
}

/// A type which holds a handle to an attribute in the attribute table
pub trait AttributeHandle {
    /// The data type which the attribute contains
    type Value: AsGatt;

    /// Returns the attribute's handle
    fn handle(&self) -> u16;
}

impl<T: AsGatt> AttributeHandle for Characteristic<T> {
    type Value = T;

    fn handle(&self) -> u16 {
        self.handle
    }
}

/// Builder for constructing GATT service definitions.
pub struct ServiceBuilder<'r, 'd, M: RawMutex, const MAX: usize> {
    handle: u16,
    start: usize,
    table: &'r mut AttributeTable<'d, M, MAX>,
}

impl<'d, M: RawMutex, const MAX: usize> ServiceBuilder<'_, 'd, M, MAX> {
    fn add_characteristic_internal<T: AsGatt>(
        &mut self,
        uuid: Uuid,
        props: CharacteristicProps,
        data: AttributeData<'d>,
    ) -> CharacteristicBuilder<'_, 'd, T, M, MAX> {
        // First the characteristic declaration
        let next = self.table.handle + 1;
        let cccd = self.table.handle + 2;
        self.table.push(Attribute {
            uuid: CHARACTERISTIC.into(),
            handle: 0,
            last_handle_in_group: 0,
            data: AttributeData::Declaration {
                props,
                handle: next,
                uuid: uuid.clone(),
            },
        });

        // Then the value declaration
        self.table.push(Attribute {
            uuid,
            handle: 0,
            last_handle_in_group: 0,
            data,
        });

        // Add optional CCCD handle
        let cccd_handle = if props.any(&[CharacteristicProp::Notify, CharacteristicProp::Indicate]) {
            self.table.push(Attribute {
                uuid: CLIENT_CHARACTERISTIC_CONFIGURATION.into(),
                handle: 0,
                last_handle_in_group: 0,
                data: AttributeData::Cccd {
                    notifications: false,
                    indications: false,
                },
            });
            Some(cccd)
        } else {
            None
        };

        CharacteristicBuilder {
            handle: Characteristic {
                handle: next,
                cccd_handle,
                phantom: PhantomData,
            },
            table: self.table,
        }
    }

    /// Add a characteristic to this service with a refererence to a mutable storage buffer.
    pub fn add_characteristic<T: AsGatt, U: Into<Uuid>>(
        &mut self,
        uuid: U,
        props: &[CharacteristicProp],
        value: T,
        store: &'d mut [u8],
    ) -> CharacteristicBuilder<'_, 'd, T, M, MAX> {
        let props = props.into();
        let bytes = value.as_gatt();
        store[..bytes.len()].copy_from_slice(bytes);
        let variable_len = T::MAX_SIZE != T::MIN_SIZE;
        let len = bytes.len() as u16;
        self.add_characteristic_internal(
            uuid.into(),
            props,
            AttributeData::Data {
                props,
                value: store,
                variable_len,
                len,
            },
        )
    }

    /// Add a characteristic to this service with a refererence to an immutable storage buffer.
    pub fn add_characteristic_ro<T: AsGatt, U: Into<Uuid>>(
        &mut self,
        uuid: U,
        value: &'d T,
    ) -> CharacteristicBuilder<'_, 'd, T, M, MAX> {
        let props = [CharacteristicProp::Read].into();
        self.add_characteristic_internal(
            uuid.into(),
            props,
            AttributeData::ReadOnlyData {
                props,
                value: value.as_gatt(),
            },
        )
    }

    /// Finish construction of the service and return a handle.
    pub fn build(self) -> u16 {
        self.handle
    }
}

impl<M: RawMutex, const MAX: usize> Drop for ServiceBuilder<'_, '_, M, MAX> {
    fn drop(&mut self) {
        let last_handle = self.table.handle;
        self.table.with_inner(|inner| {
            for item in inner.attributes[self.start..].iter_mut() {
                item.last_handle_in_group = last_handle;
            }
        });

        // Jump to next 16-aligned
        self.table.handle = self.table.handle + (0x10 - (self.table.handle % 0x10));
    }
}

/// Builder for characteristics.
pub struct CharacteristicBuilder<'r, 'd, T: AsGatt, M: RawMutex, const MAX: usize> {
    handle: Characteristic<T>,
    table: &'r mut AttributeTable<'d, M, MAX>,
}

impl<'d, T: AsGatt, M: RawMutex, const MAX: usize> CharacteristicBuilder<'_, 'd, T, M, MAX> {
    fn add_descriptor_internal<DT: AsGatt>(
        &mut self,
        uuid: Uuid,
        props: CharacteristicProps,
        data: AttributeData<'d>,
    ) -> Descriptor<DT> {
        let handle = self.table.handle;
        self.table.push(Attribute {
            uuid,
            handle: 0,
            last_handle_in_group: 0,
            data,
        });

        Descriptor {
            handle,
            phantom: PhantomData,
        }
    }

    /// Add a characteristic descriptor for this characteristic.
    pub fn add_descriptor<DT: AsGatt, U: Into<Uuid>>(
        &mut self,
        uuid: U,
        props: &[CharacteristicProp],
        data: &'d mut [u8],
    ) -> Descriptor<DT> {
        let props = props.into();
        let len = data.len() as u16;
        self.add_descriptor_internal(
            uuid.into(),
            props,
            AttributeData::Data {
                props,
                value: data,
                variable_len: false,
                len,
            },
        )
    }

    /// Add a read only characteristic descriptor for this characteristic.
    pub fn add_descriptor_ro<DT: AsGatt, U: Into<Uuid>>(&mut self, uuid: U, data: &'d [u8]) -> Descriptor<DT> {
        let props = [CharacteristicProp::Read].into();
        self.add_descriptor_internal(uuid.into(), props, AttributeData::ReadOnlyData { props, value: data })
    }

    /// Return the built characteristic.
    pub fn build(self) -> Characteristic<T> {
        self.handle
    }
}
