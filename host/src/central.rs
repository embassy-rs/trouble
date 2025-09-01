//! Functionality for the BLE central role.
use bt_hci::cmd::le::{LeAddDeviceToFilterAcceptList, LeClearFilterAcceptList, LeCreateConn, LeExtCreateConn};
use bt_hci::controller::{Controller, ControllerCmdAsync, ControllerCmdSync};
use bt_hci::param::{AddrKind, BdAddr, InitiatingPhy, LeConnRole, PhyParams};
use embassy_futures::select::{select, Either};

use crate::connection::{ConnectConfig, Connection, PhySet};
use crate::{bt_hci_duration, BleHostError, Error, PacketPool, Stack};

/// A type implementing the BLE central role.
pub struct Central<'stack, C, P: PacketPool> {
    pub(crate) stack: &'stack Stack<'stack, C, P>,
}

impl<'stack, C: Controller, P: PacketPool> Central<'stack, C, P> {
    pub(crate) fn new(stack: &'stack Stack<'stack, C, P>) -> Self {
        Self { stack }
    }

    /// Attempt to create a connection with the provided config.
    pub async fn connect(&mut self, config: &ConnectConfig<'_>) -> Result<Connection<'stack, P>, BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
            + ControllerCmdAsync<LeCreateConn>,
    {
        if config.scan_config.filter_accept_list.is_empty() {
            return Err(Error::ConfigFilterAcceptListIsEmpty.into());
        }

        let host = &self.stack.host;
        let _drop = crate::host::OnDrop::new(|| {
            host.connect_command_state.cancel(true);
        });
        host.connect_command_state.request().await;

        self.set_accept_filter(config.scan_config.filter_accept_list).await?;

        host.async_command(LeCreateConn::new(
            bt_hci_duration(config.scan_config.interval),
            bt_hci_duration(config.scan_config.window),
            true,
            AddrKind::PUBLIC,
            BdAddr::default(),
            host.address.map(|a| a.kind).unwrap_or(AddrKind::PUBLIC),
            bt_hci_duration(config.connect_params.min_connection_interval),
            bt_hci_duration(config.connect_params.max_connection_interval),
            config.connect_params.max_latency,
            bt_hci_duration(config.connect_params.supervision_timeout),
            bt_hci_duration(config.connect_params.min_event_length),
            bt_hci_duration(config.connect_params.max_event_length),
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
    ) -> Result<Connection<'stack, P>, BleHostError<C::Error>>
    where
        C: ControllerCmdSync<LeClearFilterAcceptList>
            + ControllerCmdSync<LeAddDeviceToFilterAcceptList>
            + ControllerCmdAsync<LeExtCreateConn>,
    {
        if config.scan_config.filter_accept_list.is_empty() {
            return Err(Error::ConfigFilterAcceptListIsEmpty.into());
        }

        let host = &self.stack.host;
        // Ensure no other connect ongoing.
        let _drop = crate::host::OnDrop::new(|| {
            host.connect_command_state.cancel(true);
        });
        host.connect_command_state.request().await;

        self.set_accept_filter(config.scan_config.filter_accept_list).await?;

        let initiating = InitiatingPhy {
            scan_interval: bt_hci_duration(config.scan_config.interval),
            scan_window: bt_hci_duration(config.scan_config.window),
            conn_interval_min: bt_hci_duration(config.connect_params.min_connection_interval),
            conn_interval_max: bt_hci_duration(config.connect_params.max_connection_interval),
            max_latency: config.connect_params.max_latency,
            supervision_timeout: bt_hci_duration(config.connect_params.supervision_timeout),
            min_ce_len: bt_hci_duration(config.connect_params.min_event_length),
            max_ce_len: bt_hci_duration(config.connect_params.max_event_length),
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
