use alloc::borrow::ToOwned;
use alloc::boxed::Box;

use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use trouble_host::prelude::*;

use super::protocol::BtpStatus;
use super::protocol::gatt::ServiceType;
use crate::ATTRIBUTE_TABLE_SIZE;

/// An attribute value, either heap-allocated or inline for small values.
#[derive(Debug)]
pub enum AttValue {
    /// Heap-allocated value for data larger than 8 bytes.
    Stored(Box<[u8]>),
    /// Inline value for data up to 8 bytes (avoids heap allocation).
    Small(heapless::Vec<u8, 8>),
}

impl AttValue {
    /// Create an `AttValue` from a byte slice, using `Small` if it fits in 8 bytes.
    pub fn from_slice(data: &[u8]) -> Self {
        if let Ok(vec) = heapless::Vec::from_slice(data) {
            Self::Small(vec)
        } else {
            Self::Stored(Box::from(data))
        }
    }
}

/// A queued attribute operation to be committed when the service is finalized.
#[derive(Debug)]
enum AttCommand {
    IncludedService {
        service_id: u16,
    },
    Characteristic {
        properties: u8,
        permissions: AttPermissions,
        uuid: Uuid,
        value: Option<AttValue>,
    },
    Descriptor {
        permissions: AttPermissions,
        uuid: Uuid,
        value: Option<AttValue>,
    },
}

impl AttCommand {
    /// Number of ATT entries this command will consume in the attribute table.
    ///
    /// Characteristics with Notify or Indicate properties use 3 entries
    /// (declaration + value + CCCD) vs 2 (declaration + value) for others.
    fn att_count(&self) -> u16 {
        const NOTIFY_OR_INDICATE: u8 = 0x30;

        match self {
            AttCommand::IncludedService { .. } | AttCommand::Descriptor { .. } => 1,
            AttCommand::Characteristic { properties, .. } => {
                if (properties & NOTIFY_OR_INDICATE) != 0 {
                    3
                } else {
                    2
                }
            }
        }
    }
}

/// Accumulates GATT service/characteristic/descriptor commands during the pre-server
/// phase, then commits them all to the `AttributeTable` on [`finalize()`](Self::finalize).
#[derive(Default, Debug)]
pub struct ServiceBuilder {
    service: Option<(ServiceType, Uuid)>,
    commands: heapless::Vec<AttCommand, 32>,
    service_id: u16,
}

impl ServiceBuilder {
    /// Create a new empty service builder.
    pub fn new() -> Self {
        Self {
            service: None,
            commands: heapless::Vec::new(),
            service_id: 0,
        }
    }
    /// Start a new service. Finalizes any previously open service first.
    pub fn add_service(
        &mut self,
        table: &mut AttributeTable<'_, NoopRawMutex, ATTRIBUTE_TABLE_SIZE>,
        service_type: ServiceType,
        uuid: Uuid,
    ) -> Result<u16, BtpStatus> {
        trace!("ServiceBuilder::add_service uuid={:?}", uuid);
        let next_handle = self.finalize(table)?;
        self.service = Some((service_type, uuid));
        self.service_id = next_handle;
        Ok(next_handle)
    }

    /// Queue an included service reference within the current service.
    pub fn add_included_service(&mut self, service_id: u16) -> Result<u16, BtpStatus> {
        if self.service.is_none() {
            return Err(BtpStatus::Fail);
        }
        let handle = self.next_handle();
        self.commands
            .push(AttCommand::IncludedService { service_id })
            .or(Err(BtpStatus::Fail))?;
        Ok(handle)
    }

    /// Queue a characteristic within the current service.
    pub fn add_characteristic(
        &mut self,
        properties: u8,
        permissions: AttPermissions,
        uuid: Uuid,
    ) -> Result<u16, BtpStatus> {
        trace!(
            "ServiceBuilder::add_characteristic uuid={:?} props={:#x}",
            uuid, properties
        );
        if self.service.is_none() {
            return Err(BtpStatus::Fail);
        }
        // next_handle() points to the declaration; +1 gives the value handle
        let handle = self.next_handle() + 1;
        self.commands
            .push(AttCommand::Characteristic {
                properties,
                permissions,
                uuid,
                value: None,
            })
            .or(Err(BtpStatus::Fail))?;
        Ok(handle)
    }

    /// Queue a descriptor on the most recently added characteristic.
    pub fn add_descriptor(&mut self, permissions: AttPermissions, uuid: Uuid) -> Result<u16, BtpStatus> {
        trace!("ServiceBuilder::add_descriptor uuid={:?}", uuid);
        if self.service.is_none() {
            return Err(BtpStatus::Fail);
        }
        let handle = self.next_handle();
        self.commands
            .push(AttCommand::Descriptor {
                permissions,
                uuid,
                value: None,
            })
            .or(Err(BtpStatus::Fail))?;
        Ok(handle)
    }

    /// Set the initial value on the most recently added characteristic or descriptor.
    pub fn set_value(&mut self, val: AttValue) -> Result<(), BtpStatus> {
        trace!("ServiceBuilder::set_value");
        if self.service.is_none() {
            return Err(BtpStatus::Fail);
        }
        let last = self.commands.last_mut().ok_or(BtpStatus::Fail)?;
        match last {
            AttCommand::Characteristic { value, .. } | AttCommand::Descriptor { value, .. } => {
                *value = Some(val);
                Ok(())
            }
            _ => Err(BtpStatus::Fail),
        }
    }

    /// Returns whether a service is currently being built.
    #[cfg(test)]
    pub fn has_service(&self) -> bool {
        self.service.is_some()
    }

    /// Returns the number of queued commands.
    #[cfg(test)]
    pub fn command_count(&self) -> usize {
        self.commands.len()
    }

    /// Handle of the next entry after the service declaration and all queued commands.
    fn next_handle(&self) -> u16 {
        self.service_id + self.commands.iter().map(|x| x.att_count()).sum::<u16>() + 1
    }

    /// Commit all queued commands to the attribute table. Returns the next available handle.
    pub fn finalize(
        &mut self,
        table: &mut AttributeTable<'_, NoopRawMutex, ATTRIBUTE_TABLE_SIZE>,
    ) -> Result<u16, BtpStatus> {
        info!("ServiceBuilder::finalize");
        if let Some((service_type, uuid)) = self.service.take() {
            let mut service = match service_type {
                ServiceType::Primary => table.add_service(Service { uuid }),
                ServiceType::Secondary => table.add_secondary_service(Service { uuid }),
            };
            let mut commands = self.commands.drain(..).peekable();
            while let Some(command) = commands.next() {
                match command {
                    AttCommand::IncludedService { service_id } => {
                        service.add_included_service(service_id).map_err(|_| BtpStatus::Fail)?;
                    }
                    AttCommand::Characteristic {
                        properties,
                        permissions,
                        uuid,
                        value,
                    } => {
                        let mut characteristic_builder = match value {
                            Some(AttValue::Stored(store)) => {
                                let init = store.to_owned();
                                // Intentional leak: the AttributeTable requires a `&'static mut`
                                // backing store that outlives the server. This is safe because
                                // `run()` (and therefore the server) can only execute once.
                                service
                                    .add_characteristic(uuid, properties, &*init, Box::leak(store))
                                    .to_raw()
                            }
                            Some(AttValue::Small(value)) => service
                                .add_characteristic_small(uuid, properties, value.as_slice())
                                .to_raw(),
                            None => service
                                .add_characteristic_small(uuid, properties, [].as_slice())
                                .to_raw(),
                        };

                        if permissions.read == PermissionLevel::EncryptionRequired
                            || permissions.read == PermissionLevel::AuthenticationRequired
                        {
                            characteristic_builder = characteristic_builder.read_permission(permissions.read);
                        }
                        if permissions.write == PermissionLevel::EncryptionRequired
                            || permissions.write == PermissionLevel::AuthenticationRequired
                        {
                            characteristic_builder = characteristic_builder.write_permission(permissions.write);
                        }

                        while let Some(AttCommand::Descriptor { .. }) = commands.peek() {
                            let Some(AttCommand::Descriptor {
                                permissions,
                                uuid,
                                value,
                            }) = commands.next()
                            else {
                                unreachable!()
                            };

                            match value {
                                Some(AttValue::Stored(store)) => {
                                    let init = store.to_owned();
                                    // Intentional leak: see comment on the characteristic
                                    // Box::leak above.
                                    characteristic_builder.add_descriptor(uuid, permissions, &*init, Box::leak(store));
                                }
                                Some(AttValue::Small(store)) => {
                                    characteristic_builder.add_descriptor_small(uuid, permissions, store.as_slice());
                                }
                                None => {
                                    characteristic_builder.add_descriptor_small(uuid, permissions, [].as_slice());
                                }
                            };
                        }
                    }
                    AttCommand::Descriptor { .. } => return Err(BtpStatus::Fail),
                }
            }
        }

        Ok(table.len() as u16 + 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_table() -> AttributeTable<'static, NoopRawMutex, ATTRIBUTE_TABLE_SIZE> {
        AttributeTable::new()
    }

    fn test_uuid() -> Uuid {
        Uuid::new_short(0x1234)
    }

    fn test_uuid2() -> Uuid {
        Uuid::new_short(0x5678)
    }

    // --- AttValue tests ---

    #[test]
    fn att_value_from_slice_small() {
        let val = AttValue::from_slice(&[1, 2, 3]);
        assert!(matches!(val, AttValue::Small(v) if v.as_slice() == [1, 2, 3]));
    }

    #[test]
    fn att_value_from_slice_exactly_8() {
        let data = [0u8; 8];
        let val = AttValue::from_slice(&data);
        assert!(matches!(val, AttValue::Small(v) if v.len() == 8));
    }

    #[test]
    fn att_value_from_slice_stored() {
        let data = [0u8; 9];
        let val = AttValue::from_slice(&data);
        assert!(matches!(val, AttValue::Stored(b) if b.len() == 9));
    }

    #[test]
    fn att_value_from_slice_empty() {
        let val = AttValue::from_slice(&[]);
        assert!(matches!(val, AttValue::Small(v) if v.is_empty()));
    }

    // --- AttCommand::att_count tests ---

    #[test]
    fn att_count_included_service() {
        let cmd = AttCommand::IncludedService { service_id: 1 };
        assert_eq!(cmd.att_count(), 1);
    }

    #[test]
    fn att_count_descriptor() {
        let cmd = AttCommand::Descriptor {
            permissions: AttPermissions::default(),
            uuid: test_uuid(),
            value: None,
        };
        assert_eq!(cmd.att_count(), 1);
    }

    #[test]
    fn att_count_characteristic_no_notify() {
        let cmd = AttCommand::Characteristic {
            properties: 0x02, // Read only
            permissions: AttPermissions::default(),
            uuid: test_uuid(),
            value: None,
        };
        assert_eq!(cmd.att_count(), 2);
    }

    #[test]
    fn att_count_characteristic_notify() {
        let cmd = AttCommand::Characteristic {
            properties: 0x10, // Notify
            permissions: AttPermissions::default(),
            uuid: test_uuid(),
            value: None,
        };
        assert_eq!(cmd.att_count(), 3);
    }

    #[test]
    fn att_count_characteristic_indicate() {
        let cmd = AttCommand::Characteristic {
            properties: 0x20, // Indicate
            permissions: AttPermissions::default(),
            uuid: test_uuid(),
            value: None,
        };
        assert_eq!(cmd.att_count(), 3);
    }

    // --- ServiceBuilder::new tests ---

    #[test]
    fn new_builder_empty() {
        let builder = ServiceBuilder::new();
        assert!(!builder.has_service());
        assert_eq!(builder.command_count(), 0);
    }

    // --- Error: operations before add_service ---

    #[test]
    fn add_characteristic_before_service_fails() {
        let mut builder = ServiceBuilder::new();
        let result = builder.add_characteristic(0x02, AttPermissions::default(), test_uuid());
        assert_eq!(result, Err(BtpStatus::Fail));
    }

    #[test]
    fn add_descriptor_before_service_fails() {
        let mut builder = ServiceBuilder::new();
        let result = builder.add_descriptor(AttPermissions::default(), test_uuid());
        assert_eq!(result, Err(BtpStatus::Fail));
    }

    #[test]
    fn set_value_before_service_fails() {
        let mut builder = ServiceBuilder::new();
        let val = AttValue::from_slice(&[1]);
        let result = builder.set_value(val);
        assert_eq!(result, Err(BtpStatus::Fail));
    }

    #[test]
    fn set_value_empty_commands_fails() {
        let mut builder = ServiceBuilder::new();
        let mut table = make_table();
        builder
            .add_service(&mut table, ServiceType::Primary, test_uuid())
            .unwrap();
        // No commands added, set_value should fail
        let val = AttValue::from_slice(&[1]);
        assert_eq!(builder.set_value(val), Err(BtpStatus::Fail));
    }

    #[test]
    fn set_value_on_included_service_fails() {
        let mut builder = ServiceBuilder::new();
        let mut table = make_table();
        builder
            .add_service(&mut table, ServiceType::Primary, test_uuid())
            .unwrap();
        builder.add_included_service(1).unwrap();
        let val = AttValue::from_slice(&[1]);
        assert_eq!(builder.set_value(val), Err(BtpStatus::Fail));
    }

    // --- Secondary service ---

    #[test]
    fn add_secondary_service_succeeds() {
        let mut builder = ServiceBuilder::new();
        let mut table = make_table();
        let handle = builder
            .add_service(&mut table, ServiceType::Secondary, test_uuid())
            .unwrap();
        assert_eq!(handle, 1);
    }

    // --- Handle calculation and finalize ---

    #[test]
    fn add_service_returns_handle() {
        let mut builder = ServiceBuilder::new();
        let mut table = make_table();
        let handle = builder
            .add_service(&mut table, ServiceType::Primary, test_uuid())
            .unwrap();
        assert_eq!(handle, 1); // first handle on empty table
    }

    #[test]
    fn characteristic_handle_calculation() {
        let mut builder = ServiceBuilder::new();
        let mut table = make_table();
        builder
            .add_service(&mut table, ServiceType::Primary, test_uuid())
            .unwrap();

        // Service handle is 1, first characteristic value handle = service_id + 0 (sum of att_counts) + 2 = 1 + 0 + 2 = 3
        let h1 = builder
            .add_characteristic(0x02, AttPermissions::default(), test_uuid())
            .unwrap();
        assert_eq!(h1, 3); // handle 2=decl, 3=value

        // After one char with att_count=2: next char value handle = 1 + 2 + 2 = 5
        let h2 = builder
            .add_characteristic(0x02, AttPermissions::default(), test_uuid2())
            .unwrap();
        assert_eq!(h2, 5);
    }

    #[test]
    fn characteristic_with_notify_handle_calculation() {
        let mut builder = ServiceBuilder::new();
        let mut table = make_table();
        builder
            .add_service(&mut table, ServiceType::Primary, test_uuid())
            .unwrap();

        // notify char: att_count=3
        let h1 = builder
            .add_characteristic(0x12, AttPermissions::default(), test_uuid())
            .unwrap();
        assert_eq!(h1, 3);

        // After one notify char (3 entries): next handle = 1 + 3 + 2 = 6
        let h2 = builder
            .add_characteristic(0x02, AttPermissions::default(), test_uuid2())
            .unwrap();
        assert_eq!(h2, 6);
    }

    #[test]
    fn descriptor_handle_calculation() {
        let mut builder = ServiceBuilder::new();
        let mut table = make_table();
        builder
            .add_service(&mut table, ServiceType::Primary, test_uuid())
            .unwrap();
        builder
            .add_characteristic(0x02, AttPermissions::default(), test_uuid())
            .unwrap();

        // After char (att_count=2), descriptor handle = 1 + 2 + 1 = 4
        let h = builder.add_descriptor(AttPermissions::default(), test_uuid2()).unwrap();
        assert_eq!(h, 4);
    }

    #[test]
    fn finalize_commits_to_table() {
        let mut builder = ServiceBuilder::new();
        let mut table = make_table();
        let initial_len = table.len();
        builder
            .add_service(&mut table, ServiceType::Primary, test_uuid())
            .unwrap();
        builder
            .add_characteristic(0x02, AttPermissions::default(), test_uuid())
            .unwrap();
        builder.finalize(&mut table).unwrap();

        // Table should have: 1 service + 2 (characteristic decl + value) = 3 new entries
        assert_eq!(table.len(), initial_len + 3);
    }

    #[test]
    fn finalize_with_notify_characteristic() {
        let mut builder = ServiceBuilder::new();
        let mut table = make_table();
        let initial_len = table.len();
        builder
            .add_service(&mut table, ServiceType::Primary, test_uuid())
            .unwrap();
        builder
            .add_characteristic(0x12, AttPermissions::default(), test_uuid())
            .unwrap();
        builder.finalize(&mut table).unwrap();

        // 1 service + 3 (decl + value + CCCD) = 4
        assert_eq!(table.len(), initial_len + 4);
    }

    #[test]
    fn finalize_no_open_service_is_noop() {
        let mut builder = ServiceBuilder::new();
        let mut table = make_table();
        let result = builder.finalize(&mut table).unwrap();
        assert_eq!(result, 1); // table.len() == 0, so next handle = 1
    }

    #[test]
    fn add_service_auto_finalizes_previous() {
        let mut builder = ServiceBuilder::new();
        let mut table = make_table();
        builder
            .add_service(&mut table, ServiceType::Primary, test_uuid())
            .unwrap();
        builder
            .add_characteristic(0x02, AttPermissions::default(), test_uuid())
            .unwrap();

        // Adding a second service auto-finalizes the first
        let h2 = builder
            .add_service(&mut table, ServiceType::Primary, test_uuid2())
            .unwrap();
        // First service: 1 service + 2 char = 3 entries => next handle = 4
        assert_eq!(h2, 4);
        assert_eq!(table.len(), 3);
    }

    #[test]
    fn finalize_standalone_descriptor_fails() {
        let mut builder = ServiceBuilder::new();
        let mut table = make_table();
        builder
            .add_service(&mut table, ServiceType::Primary, test_uuid())
            .unwrap();
        // Push a descriptor directly (without a preceding characteristic)
        // We can't call add_descriptor without going through the builder, but the
        // finalize code checks for a standalone descriptor. We test via the builder:
        builder.add_descriptor(AttPermissions::default(), test_uuid()).unwrap();
        let result = builder.finalize(&mut table);
        assert_eq!(result, Err(BtpStatus::Fail));
    }

    #[test]
    fn finalize_included_service_succeeds() {
        let mut builder = ServiceBuilder::new();
        let mut table = make_table();
        let initial_len = table.len();
        builder
            .add_service(&mut table, ServiceType::Primary, test_uuid())
            .unwrap();
        builder.add_included_service(1).unwrap();
        builder.finalize(&mut table).unwrap();
        // 1 service + 1 included service = 2 entries
        assert_eq!(table.len(), initial_len + 2);
    }

    #[test]
    fn set_value_on_characteristic() {
        let mut builder = ServiceBuilder::new();
        let mut table = make_table();
        builder
            .add_service(&mut table, ServiceType::Primary, test_uuid())
            .unwrap();
        builder
            .add_characteristic(0x02, AttPermissions::default(), test_uuid())
            .unwrap();
        let val = AttValue::from_slice(&[0xAA, 0xBB]);
        assert!(builder.set_value(val).is_ok());
        builder.finalize(&mut table).unwrap();
    }

    #[test]
    fn set_value_on_descriptor() {
        let mut builder = ServiceBuilder::new();
        let mut table = make_table();
        builder
            .add_service(&mut table, ServiceType::Primary, test_uuid())
            .unwrap();
        builder
            .add_characteristic(0x02, AttPermissions::default(), test_uuid())
            .unwrap();
        builder.add_descriptor(AttPermissions::default(), test_uuid2()).unwrap();
        let val = AttValue::from_slice(&[0xCC]);
        assert!(builder.set_value(val).is_ok());
        builder.finalize(&mut table).unwrap();
    }

    #[test]
    fn finalize_with_descriptor_attached_to_characteristic() {
        let mut builder = ServiceBuilder::new();
        let mut table = make_table();
        let initial_len = table.len();
        builder
            .add_service(&mut table, ServiceType::Primary, test_uuid())
            .unwrap();
        builder
            .add_characteristic(0x02, AttPermissions::default(), test_uuid())
            .unwrap();
        builder.add_descriptor(AttPermissions::default(), test_uuid2()).unwrap();
        builder.finalize(&mut table).unwrap();

        // 1 service + 2 (char) + 1 (descriptor) = 4
        assert_eq!(table.len(), initial_len + 4);
    }
}
