
pub mod command_complete;
pub mod command_status;
pub mod data_buffer_overflow;
pub mod disconnection_complete;
pub mod encryption_change;
pub mod encryption_key_refresh_complete;
pub mod hardware_error;
pub mod le_advertising_report;
pub mod le_advertising_set_terminated;
pub mod le_big_info_advertising_report;
pub mod le_big_sync_established;
pub mod le_big_sync_lost;
pub mod le_channel_selection_algorithm;
pub mod le_cis_established;
pub mod le_cis_request;
pub mod le_connection_complete;
pub mod le_connection_iq_report;
pub mod le_connection_update_complete;
pub mod le_connectionless_iq_report;
pub mod le_create_big_complete;
pub mod le_cte_request_failed;
pub mod le_data_length_change;
pub mod le_directed_advertising_report;
pub mod le_enhanced_connection_complete;
pub mod le_extended_advertising_report_event;
pub mod le_generate_dhkey_complete;
pub mod le_long_term_key_request;
pub mod le_path_loss_threshold;
pub mod le_periodic_advertising_report;
pub mod le_periodic_advertising_sync_established;
pub mod le_periodic_advertising_sync_lost;
pub mod le_period_advertising_sync_transfer_received;
pub mod le_phy_update_complete;
pub mod le_read_local_p256_public_key_complete;
pub mod le_read_remote_features_complete;
pub mod le_remote_connection_parameter_request;
pub mod le_request_peer_sca_complete;
pub mod le_scan_request_received;
pub mod le_scan_timeout;
pub mod le_terminate_big_complete;
pub mod le_transmit_power_reporting;
pub mod number_of_completed_packets;
pub mod read_remote_version_information_complete;

pub trait Event {

}