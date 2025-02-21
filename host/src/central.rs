//! Functionality for the BLE central role.
use bt_hci::cmd::le::{LeAddDeviceToFilterAcceptList, LeClearFilterAcceptList, LeCreateConn, LeExtCreateConn};
use bt_hci::controller::{Controller, ControllerCmdAsync, ControllerCmdSync};
use bt_hci::param::{AddrKind, BdAddr, InitiatingPhy, LeConnRole, PhyParams};
use embassy_futures::select::{Either, select};

use crate::connection::{ConnectConfig, Connection, PhySet};
use crate::{BleHostError, Error, Stack};

/// A type implementing the BLE central role.
pub struct Central<'stack, C> {
    pub(crate) stack: &'stack Stack<'stack, C>,
}

impl<'stack, C: Controller> Central<'stack, C> {
    pub(crate) fn new(stack: &'stack Stack<'stack, C>) -> Self {
        Self { stack }
    }

    /// Attempt to create a connection with the provided config.
    pub async fn connect(&mut self, config: &ConnectConfig<'_>) -> Result<Connection<'stack>, BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
            + ControllerCmdAsync<LeCreateConn>,
    {
        if config.scan_config.filter_accept_list.is_empty() {
            return Err(Error::InvalidValue.into());
        }

        let host = &self.stack.host;
        let _drop = crate::host::OnDrop::new(|| {
            host.connect_command_state.cancel(true);
        });
        host.connect_command_state.request().await;

        self.set_accept_filter(config.scan_config.filter_accept_list).await?;

        host.async_command(LeCreateConn::new(
            config.scan_config.interval.into(),
            config.scan_config.window.into(),
            true,
            AddrKind::PUBLIC,
            BdAddr::default(),
            host.address.map(|a| a.kind).unwrap_or(AddrKind::PUBLIC),
            config.connect_params.min_connection_interval.into(),
            config.connect_params.max_connection_interval.into(),
            config.connect_params.max_latency,
            config.connect_params.supervision_timeout.into(),
            config.connect_params.event_length.into(),
            config.connect_params.event_length.into(),
        ))
        .await?;
        match select(
            host.connections
                .accept(LeConnRole::Central, config.scan_config.filter_accept_list),
            host.connect_command_state.wait_idle(),
        )
        .await
        {
            Either::First(conn) => {
                _drop.defuse();
                host.connect_command_state.done();
                Ok(conn)
            }
            Either::Second(_) => Err(Error::Timeout.into()),
        }
    }

    /// Attempt to create a connection with the provided config.
    pub async fn connect_ext(
        &mut self,
        config: &ConnectConfig<'_>,
    ) -> Result<Connection<'stack>, BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
            + ControllerCmdAsync<LeExtCreateConn>,
    {
        if config.scan_config.filter_accept_list.is_empty() {
            return Err(Error::InvalidValue.into());
        }

        let host = &self.stack.host;
        // Ensure no other connect ongoing.
        let _drop = crate::host::OnDrop::new(|| {
            host.connect_command_state.cancel(true);
        });
        host.connect_command_state.request().await;

        self.set_accept_filter(config.scan_config.filter_accept_list).await?;

        let initiating = InitiatingPhy {
            scan_interval: config.scan_config.interval.into(),
            scan_window: config.scan_config.window.into(),
            conn_interval_min: config.connect_params.min_connection_interval.into(),
            conn_interval_max: config.connect_params.max_connection_interval.into(),
            max_latency: config.connect_params.max_latency,
            supervision_timeout: config.connect_params.supervision_timeout.into(),
            min_ce_len: config.connect_params.event_length.into(),
            max_ce_len: config.connect_params.event_length.into(),
        };
        let phy_params = create_phy_params(initiating, config.scan_config.phys);

        host.async_command(LeExtCreateConn::new(
            true,
            host.address.map(|a| a.kind).unwrap_or(AddrKind::PUBLIC),
            AddrKind::PUBLIC,
            BdAddr::default(),
            phy_params,
        ))
        .await?;

        match select(
            host.connections
                .accept(LeConnRole::Central, config.scan_config.filter_accept_list),
            host.connect_command_state.wait_idle(),
        )
        .await
        {
            Either::First(conn) => {
                _drop.defuse();
                host.connect_command_state.done();
                Ok(conn)
            }
            Either::Second(_) => Err(Error::Timeout.into()),
        }
    }

    pub(crate) async fn set_accept_filter(
        &mut self,
        filter_accept_list: &[(AddrKind, &BdAddr)],
    ) -> Result<(), BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeClearFilterAcceptList> + ControllerCmdSync<LeAddDeviceToFilterAcceptList>,
    {
        let host = &self.stack.host;
        host.command(LeClearFilterAcceptList::new()).await?;
        for entry in filter_accept_list {
            host.command(LeAddDeviceToFilterAcceptList::new(entry.0, *entry.1))
                .await?;
        }
        Ok(())
    }

    /// Initiate pairing
    #[cfg(feature = "security")]
    pub async fn pairing(&self, connection: &Connection<'stack>) -> Result<(), BleHostError<C::Error>> {
        let sm = &self.stack.host.connections.security_manager;
        sm.initiate(connection)?;
        let reason = sm.get_result().await;
        if reason == crate::security_manager::Reason::Success {
            Ok(())
        } else {
            Err(BleHostError::BleHost(Error::Security(reason)))
        }
    }
}

pub(crate) fn create_phy_params<P: Copy>(phy: P, phys: PhySet) -> PhyParams<P> {
    let phy_params: PhyParams<P> = PhyParams {
        le_1m_phy: match phys {
            PhySet::M1 | PhySet::M1M2 | PhySet::M1Coded | PhySet::M1M2Coded => Some(phy),
            _ => None,
        },
        le_2m_phy: match phys {
            PhySet::M2 | PhySet::M1M2 | PhySet::M2Coded | PhySet::M1M2Coded => Some(phy),
            _ => None,
        },
        le_coded_phy: match phys {
            PhySet::M2Coded | PhySet::Coded | PhySet::M1Coded | PhySet::M1M2Coded => Some(phy),
            _ => None,
        },
    };
    phy_params
}
