#!/usr/bin/env python3
# Copyright (C) 2019 Checkmk GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

import pytest

from tests.unit.conftest import FixPluginLegacy

from cmk.utils.sectionname import SectionName

from cmk.base.api.agent_based.register import AgentBasedPlugins

from cmk.agent_based.legacy.v0_unstable import LegacyCheckDefinition
from cmk.discover_plugins import PluginLocation

pytestmark = pytest.mark.checks


def _was_maincheck(lcd: LegacyCheckDefinition) -> bool:
    return lcd.sections is None


def test_create_section_plugin_from_legacy(
    fix_plugin_legacy: FixPluginLegacy, agent_based_plugins: AgentBasedPlugins
) -> None:
    for check_info_dict in fix_plugin_legacy.check_info.values():
        # only test main checks
        if not _was_maincheck(check_info_dict):
            continue

        section_name = SectionName(check_info_dict.name)

        section = (
            agent_based_plugins.agent_sections.get(section_name)
            or agent_based_plugins.snmp_sections[section_name]
        )

        if (original_parse_function := check_info_dict.parse_function) is not None:
            assert original_parse_function.__name__ == section.parse_function.__name__


def test_snmp_info_snmp_detect_equal(fix_plugin_legacy: FixPluginLegacy) -> None:
    for check_info_element in fix_plugin_legacy.check_info.values():
        assert (check_info_element.detect is None) is (check_info_element.fetch is None)


def _defines_section(check_info_element: LegacyCheckDefinition) -> bool:
    if check_info_element.parse_function is not None:
        return True

    assert check_info_element.detect is None
    assert check_info_element.fetch is None
    return False


def _is_section_migrated(name: str, agent_based_plugins: AgentBasedPlugins) -> bool:
    sname = SectionName(name)
    return (
        section := agent_based_plugins.snmp_sections.get(
            sname, agent_based_plugins.agent_sections.get(sname)
        )
    ) is not None and isinstance(section.location, PluginLocation)


def test_sections_definitions_exactly_in_mainchecks(
    fix_plugin_legacy: FixPluginLegacy, agent_based_plugins: AgentBasedPlugins
) -> None:
    """Test where section definitions occur.

    Make sure that sections are defined if and only if it is a main check
    for which no migrated section exists.
    """
    for check_info_element in fix_plugin_legacy.check_info.values():
        if not _was_maincheck(check_info_element):  # subcheck
            assert not _defines_section(check_info_element)
        else:
            assert _is_section_migrated(
                check_info_element.name, agent_based_plugins
            ) is not _defines_section(check_info_element)


def test_all_checks_migrated(
    fix_plugin_legacy: FixPluginLegacy, agent_based_plugins: AgentBasedPlugins
) -> None:
    migrated = {str(name) for name in agent_based_plugins.check_plugins}
    # we don't expect pure section declarations anymore
    true_checks = {lcd.name for lcd in fix_plugin_legacy.check_info.values() if lcd.check_function}
    failures = true_checks - migrated
    assert not failures, f"failed to migrate: {failures!r}"


def test_no_new_or_vanished_legacy_checks(fix_plugin_legacy: FixPluginLegacy) -> None:
    expected_legacy_checks = {
        "3ware_disks",
        "3ware_info",
        "3ware_units",
        "acme_certificates",
        "acme_fan",
        "acme_powersupply",
        "acme_sbc_snmp",
        "acme_temp",
        "acme_voltage",
        "ad_replication",
        "adva_fsp_temp",
        "aironet_errors",
        "aix_hacmp_resources",
        "aix_paging",
        "akcp_daisy_temp",
        "alcatel_temp",
        "alcatel_temp_aos7",
        "alcatel_timetra_cpu",
        "allnet_ip_sensoric_tension",
        "allnet_ip_sensoric_temp",
        "allnet_ip_sensoric_humidity",
        "allnet_ip_sensoric_pressure",
        "apc_ats_status",
        "apc_humidity",
        "apc_inrow_airflow",
        "apc_inrow_temp",
        "apc_rackpdu_power",
        "apc_sts_inputs",
        "apc_symmetra",
        "apc_symmetra_temp",
        "apc_symmetra_elphase",
        "apc_symmetra_ext_temp",
        "apc_symmetra_input",
        "apc_symmetra_output",
        "apc_symmetra_test",
        "appdynamics_memory",
        "appdynamics_sessions",
        "appdynamics_web_container",
        "arris_cmts_cpu",
        "arris_cmts_mem",
        "arris_cmts_temp",
        "artec_temp",
        "aruba_cpu_util",
        "atto_fibrebridge_chassis_temp",
        "atto_fibrebridge_chassis",
        "atto_fibrebridge_fcport",
        "avaya_45xx_cpu",
        "avaya_45xx_temp",
        "avaya_88xx",
        "avaya_88xx_fan",
        "avaya_88xx_cpu",
        "avaya_chassis_temp",
        "aws_cloudwatch_alarms_limits",
        "aws_costs_and_usage",
        "aws_costs_and_usage_per_service",
        "aws_dynamodb_limits",
        "aws_dynamodb_summary",
        "aws_dynamodb_table",
        "aws_dynamodb_table_read_capacity",
        "aws_dynamodb_table_write_capacity",
        "aws_dynamodb_table_latency",
        "aws_ebs_summary",
        "aws_ebs_summary_health",
        "aws_ec2_limits",
        "aws_ec2_security_groups",
        "aws_elb",
        "aws_elb_latency",
        "aws_elb_http_elb",
        "aws_elb_http_backend",
        "aws_elb_healthy_hosts",
        "aws_elb_backend_connection_errors",
        "aws_elb_health",
        "aws_elb_limits",
        "aws_elb_summary",
        "aws_elbv2_application",
        "aws_elbv2_application_connections",
        "aws_elbv2_application_http_elb",
        "aws_elbv2_application_http_redirects",
        "aws_elbv2_application_statistics",
        "aws_elbv2_application_target_groups_http",
        "aws_elbv2_application_target_groups_lambda",
        "aws_elbv2_limits",
        "aws_elbv2_network",
        "aws_elbv2_network_connections",
        "aws_elbv2_network_tls_handshakes",
        "aws_elbv2_network_rst_packets",
        "aws_elbv2_network_statistics",
        "aws_elbv2_summary",
        "aws_elbv2_summary_network",
        "aws_elbv2_target_groups",
        "aws_elbv2_target_groups_network",
        "aws_glacier",
        "aws_glacier_summary",
        "aws_glacier_limits",
        "aws_rds_limits",
        "aws_rds_summary",
        "aws_rds_summary_db_status",
        "aws_s3",
        "aws_s3_summary",
        "aws_s3_limits",
        "aws_s3_requests",
        "aws_s3_requests_http_errors",
        "aws_s3_requests_latency",
        "aws_s3_requests_traffic_stats",
        "aws_s3_requests_select_object",
        "aws_wafv2_limits",
        "aws_wafv2_summary",
        "aws_wafv2_web_acl",
        "azure_ad",
        "azure_ad_sync",
        "azure_agent_info",
        "azure_databases_storage",
        "azure_databases_deadlock",
        "azure_databases_cpu",
        "azure_databases_dtu",
        "azure_databases_connections",
        "azure_databases",
        "azure_sites",
        "azure_storageaccounts",
        "azure_storageaccounts_flow",
        "azure_storageaccounts_performance",
        "azure_usagedetails",
        "barracuda_mail_latency",
        "barracuda_mailqueues",
        "barracuda_system_cpu_util",
        "bintec_cpu",
        "bintec_sensors",
        "bintec_sensors_fan",
        "bintec_sensors_temp",
        "bintec_sensors_voltage",
        "blade_bays",
        "blade_bx_powerfan",
        "blade_bx_temp",
        "bluecat_command_server",
        "bluecat_ha",
        "bluecat_ntp",
        "bluecat_threads",
        "bluenet_meter",
        "bluenet_sensor",
        "bluenet_sensor_hum",
        "brocade",
        "brocade_fan",
        "brocade_power",
        "brocade_temp",
        "brocade_mlx",
        "brocade_mlx_module_status",
        "brocade_mlx_module_mem",
        "brocade_mlx_module_cpu",
        "brocade_mlx_temp",
        "brocade_sys_mem",
        "brocade_sys",
        "brocade_tm",
        "bvip_fans",
        "bvip_link",
        "bvip_poe",
        "bvip_temp",
        "bvip_util",
        "cadvisor_cpu",
        "cadvisor_df",
        "cadvisor_memory",
        "carel_sensors",
        "casa_cpu_mem",
        "casa_cpu_temp",
        "casa_cpu_util",
        "checkpoint_fan",
        "checkpoint_memory",
        "checkpoint_packets",
        "checkpoint_temp",
        "checkpoint_tunnels",
        "checkpoint_voltage",
        "checkpoint_vsx",
        "checkpoint_vsx_connections",
        "checkpoint_vsx_packets",
        "checkpoint_vsx_traffic",
        "checkpoint_vsx_status",
        "cisco_asa_connections",
        "cisco_cpu",
        "cisco_fru_powerusage",
        "cisco_ip_sla",
        "cisco_nexus_cpu",
        "cisco_oldcpu",
        "cisco_prime_wifi_access_points",
        "cisco_prime_wifi_connections",
        "cisco_srst_state",
        "cisco_sys_mem",
        "cisco_ucs_cpu",
        "cisco_ucs_hdd",
        "cisco_ucs_lun",
        "cisco_ucs_mem_total",
        "cisco_ucs_raid",
        "cisco_ucs_system",
        "cisco_ucs_temp_env",
        "cisco_ucs_temp_mem",
        "cisco_vpn_sessions",
        "citrix_licenses",
        "citrix_serverload",
        "citrix_sessions",
        "climaveneta_fan",
        "climaveneta_temp",
        "cmc_temp",
        "cmciii_lcp_water",
        "cmctc_temp",
        "couchbase_buckets_cache",
        "couchbase_buckets_fragmentation",
        "couchbase_buckets_items",
        "couchbase_buckets_mem",
        "couchbase_buckets_operations",
        "couchbase_buckets_operations_total",
        "couchbase_buckets_vbuckets",
        "couchbase_buckets_vbuckets_replica",
        "couchbase_nodes_cache",
        "couchbase_nodes_info",
        "couchbase_nodes_items",
        "couchbase_nodes_operations",
        "couchbase_nodes_operations_total",
        "couchbase_nodes_size",
        "couchbase_nodes_size_docs",
        "couchbase_nodes_size_spacial_views",
        "couchbase_nodes_size_couch_views",
        "couchbase_nodes_stats",
        "couchbase_nodes_stats_cpu_util",
        "couchbase_nodes_stats_mem",
        "cups_queues",
        "datapower_cpu",
        "datapower_fs",
        "datapower_mem",
        "datapower_temp",
        "db2_backup",
        "db2_bp_hitratios",
        "db2_connections",
        "db2_counters",
        "db2_logsizes",
        "db2_mem",
        "db2_sort_overflow",
        "db2_tablespaces",
        "ddn_s2a_errors",
        "ddn_s2a_faultsbasic_disks",
        "ddn_s2a_faultsbasic_temp",
        "ddn_s2a_faultsbasic_ps",
        "ddn_s2a_faultsbasic_fans",
        "ddn_s2a_faultsbasic_pingfault",
        "ddn_s2a_faultsbasic_bootstatus",
        "ddn_s2a_faultsbasic_cachecoh",
        "ddn_s2a_faultsbasic_dualcomm",
        "ddn_s2a_faultsbasic_ethernet",
        "ddn_s2a_faultsbasic",
        "ddn_s2a_stats_readhits",
        "ddn_s2a_stats_io",
        "ddn_s2a_stats",
        "ddn_s2a_statsdelay",
        "ddn_s2a_uptime",
        "ddn_s2a_version",
        "decru_fans",
        "decru_perf",
        "decru_temps",
        "dell_chassis_temp",
        "dell_compellent_controller",
        "dell_compellent_disks",
        "dell_compellent_enclosure",
        "dell_compellent_folder",
        "dell_idrac_fans",
        "dell_om_fans",
        "dell_om_sensors",
        "dell_om_vdisks",
        "dell_powerconnect_cpu",
        "dell_powerconnect_temp",
        "dell_poweredge_amperage",
        "dell_poweredge_amperage_power",
        "dell_poweredge_amperage_current",
        "dell_poweredge_cpu",
        "dell_poweredge_mem",
        "dell_poweredge_netdev",
        "dell_poweredge_pci",
        "dell_poweredge_status",
        "dell_poweredge_temp",
        "didactum_can_sensors_analog",
        "didactum_can_sensors_analog_humidity",
        "didactum_can_sensors_analog_voltage",
        "didactum_sensors_analog",
        "didactum_sensors_analog_humidity",
        "didactum_sensors_analog_voltage",
        "didactum_sensors_discrete",
        "didactum_sensors_outlet",
        "docker_node_disk_usage",
        "docker_node_info",
        "docker_node_info_containers",
        "docsis_channels_downstream",
        "docsis_channels_upstream",
        "docsis_cm_status",
        "domino_mailqueues",
        "domino_transactions",
        "domino_users",
        "dotnet_clrmemory",
        "elasticsearch_cluster_health",
        "elasticsearch_cluster_health_shards",
        "elasticsearch_cluster_health_tasks",
        "elasticsearch_nodes",
        "eltek_battery",
        "eltek_battery_temp",
        "eltek_battery_supply",
        "eltek_fans",
        "eltek_outdoor_temp",
        "eltek_systemstatus",
        "emc_datadomain_disks",
        "emc_datadomain_fans",
        "emc_datadomain_fs",
        "emc_datadomain_mtree",
        "emc_datadomain_nvbat",
        "emc_datadomain_power",
        "emc_datadomain_temps",
        "emc_isilon",
        "emc_isilon_clusterhealth",
        "emc_isilon_nodehealth",
        "emc_isilon_nodes",
        "emc_isilon_names",
        "emc_isilon_cpu",
        "emc_isilon_diskstatus",
        "emc_isilon_fans",
        "emc_isilon_ifs",
        "emc_isilon_power",
        "emc_isilon_temp",
        "emc_isilon_temp_cpu",
        "emc_vplex_cpu",
        "emcvnx_agent",
        "emcvnx_disks",
        "emcvnx_hba",
        "emcvnx_hwstatus",
        "emcvnx_info",
        "emcvnx_info_storage",
        "emcvnx_info_link",
        "emcvnx_info_config",
        "emcvnx_info_io",
        "emcvnx_mirrorview",
        "emcvnx_raidgroups",
        "emcvnx_raidgroups_list_luns",
        "emcvnx_raidgroups_list_disks",
        "emcvnx_raidgroups_capacity",
        "emcvnx_raidgroups_capacity_contiguous",
        "emcvnx_sp_util",
        "emcvnx_storage_pools",
        "emcvnx_storage_pools_tiering",
        "emcvnx_storage_pools_tieringtypes",
        "emcvnx_storage_pools_deduplication",
        "emcvnx_writecache",
        "emerson_stat",
        "emerson_temp",
        "emka_modules",
        "emka_modules_alarm",
        "emka_modules_handle",
        "emka_modules_sensor_volt",
        "emka_modules_sensor_temp",
        "emka_modules_sensor_humid",
        "emka_modules_relay",
        "enterasys_cpu_util",
        "enterasys_fans",
        "enterasys_lsnat",
        "enterasys_powersupply",
        "enterasys_temp",
        "entersekt",
        "entersekt_emrerrors",
        "entersekt_ecerterrors",
        "entersekt_soaperrors",
        "entersekt_certexpiry",
        "epson_beamer_lamp",
        "esx_vsphere_counters_uptime",
        "esx_vsphere_counters_swap",
        "esx_vsphere_datastores",
        "esx_vsphere_hostsystem_state",
        "esx_vsphere_hostsystem_maintenance",
        "esx_vsphere_hostsystem_multipath",
        "esx_vsphere_licenses",
        "esx_vsphere_objects",
        "esx_vsphere_objects_count",
        "esx_vsphere_sensors",
        "esx_vsphere_vm_mounted_devices",
        "etherbox2_temp",
        "f5_bigip_apm",
        "f5_bigip_chassis_temp",
        "f5_bigip_conns",
        "f5_bigip_cpu_temp",
        "f5_bigip_fans",
        "f5_bigip_interfaces",
        "f5_bigip_mem",
        "f5_bigip_pool",
        "f5_bigip_psu",
        "f5_bigip_snat",
        "f5_bigip_vserver",
        "fast_lta_headunit",
        "fast_lta_headunit_status",
        "fast_lta_headunit_replication",
        "fast_lta_silent_cubes",
        "fast_lta_silent_cubes_capacity",
        "fast_lta_volumes",
        "fc_port",
        "filehandler",
        "filestats_single",
        "filestats",
        "fireeye_active_vms",
        "fireeye_bypass",
        "fireeye_content",
        "fireeye_fans",
        "fireeye_lic_active",
        "fireeye_lic_expiration",
        "fireeye_mail",
        "fireeye_mail_attachment",
        "fireeye_mail_url",
        "fireeye_mail_statistics",
        "fireeye_mail_received",
        "fireeye_mailq",
        "fireeye_powersupplies",
        "fireeye_quarantine",
        "fireeye_raid",
        "fireeye_raid_disks",
        "fireeye_smtp_conn",
        "fireeye_sys_image",
        "fireeye_temp",
        "fortigate_cpu",
        "fortigate_cpu_base",
        "fortigate_ipsecvpn",
        "fortigate_memory",
        "fortigate_memory_base",
        "fortigate_node",
        "fortigate_node_cpu",
        "fortigate_node_sessions",
        "fortigate_sessions",
        "fortigate_sessions_base",
        "fortigate_sslvpn",
        "fortinet_controller_aps",
        "fortisandbox_cpu_util",
        "fortisandbox_queues",
        "fsc_fans",
        "fsc_ipmi_mem_status",
        "fsc_sc2_cpu_status",
        "fsc_sc2_fans",
        "fsc_sc2_info",
        "fsc_sc2_mem_status",
        "fsc_sc2_power_consumption",
        "fsc_sc2_psu",
        "fsc_sc2_temp",
        "fsc_sc2_voltage",
        "fsc_subsystems",
        "fsc_temp",
        "genua_carp",
        "genua_fan",
        "genua_pfstate",
        "genua_state_correlation",
        "genua_vpn",
        "graylog_cluster_stats",
        "graylog_cluster_stats_elastic",
        "graylog_cluster_stats_mongodb",
        "graylog_cluster_traffic",
        "graylog_jvm",
        "graylog_license",
        "graylog_messages",
        "graylog_nodes",
        "graylog_sidecars",
        "graylog_sources",
        "gude_humidity",
        "gude_powerbanks",
        "gude_relayport",
        "gude_temp",
        "h3c_lanswitch_cpu",
        "h3c_lanswitch_sensors",
        "heartbeat_nodes",
        "heartbeat_rscstatus",
        "hepta",
        "hepta_syncmoduletimesyncstate",
        "hepta_ntpsysstratum",
        "hepta_syncmoduletimelocal",
        "hitachi_hnas_bossock",
        "hitachi_hnas_cifs",
        "hitachi_hnas_cpu",
        "hitachi_hnas_drives",
        "hitachi_hnas_fan",
        "hitachi_hnas_fpga",
        "hitachi_hnas_pnode",
        "hitachi_hnas_psu",
        "hitachi_hnas_quorumdevice",
        "hitachi_hnas_temp",
        "hitachi_hnas_vnode",
        "hitachi_hus_status",
        "hivemanager_devices",
        "hivemanager_ng_devices",
        "hp_blade",
        "hp_blade_blades",
        "hp_blade_fan",
        "hp_blade_manager",
        "hp_blade_psu",
        "hp_eml_sum",
        "hp_fan",
        "hp_hh3c_ext",
        "hp_hh3c_ext_states",
        "hp_hh3c_ext_cpu",
        "hp_hh3c_ext_mem",
        "hp_mcs_sensors",
        "hp_mcs_sensors_fan",
        "hp_mcs_system",
        "hp_procurve_cpu",
        "hp_procurve_mem",
        "hp_procurve_sensors",
        "hp_procurve_temp",
        "hp_proliant",
        "hp_proliant_cpu",
        "hp_proliant_da_cntlr",
        "hp_proliant_raid",
        "hp_proliant_temp",
        "hp_psu_temp",
        "hp_psu",
        "hp_sts_drvbox",
        "hp_webmgmt_status",
        "hpux_fchba",
        "hpux_multipath",
        "hpux_serviceguard",
        "hpux_snmp_cs",
        "hpux_snmp_cs_cpu",
        "hpux_tunables",
        "hpux_tunables_nkthread",
        "hpux_tunables_nproc",
        "hpux_tunables_maxfiles_lim",
        "hpux_tunables_semmni",
        "hpux_tunables_shmseg",
        "hpux_tunables_semmns",
        "hr_cpu",
        "huawei_osn_fan",
        "huawei_osn_laser",
        "huawei_osn_power",
        "huawei_osn_temp",
        "huawei_switch_cpu",
        "huawei_switch_fan",
        "huawei_switch_mem",
        "huawei_switch_psu",
        "huawei_switch_stack",
        "huawei_switch_temp",
        "huawei_wlc_aps",
        "huawei_wlc_aps_status",
        "huawei_wlc_aps_cpu",
        "huawei_wlc_aps_mem",
        "huawei_wlc_aps_temp",
        "huawei_wlc_devs",
        "huawei_wlc_devs_mem",
        "huawei_wlc_devs_cpu",
        "hwg_humidity",
        "hwg_ste2",
        "hwg_ste2_humidity",
        "hwg_temp",
        "hyperv_checkpoints",
        "hyperv_vms",
        "hyperv_vmstatus",
        "ibm_imm_fan",
        "ibm_imm_health",
        "ibm_imm_voltage",
        "ibm_mq_channels",
        "ibm_mq_managers",
        "ibm_mq_plugin",
        "ibm_mq_queues",
        "ibm_rsa_health",
        "ibm_storage_ts",
        "ibm_storage_ts_status",
        "ibm_storage_ts_library",
        "ibm_storage_ts_drive",
        "ibm_svc_array",
        "ibm_svc_disks",
        "ibm_svc_enclosure",
        "ibm_svc_enclosurestats",
        "ibm_svc_enclosurestats_temp",
        "ibm_svc_enclosurestats_power",
        "ibm_svc_eventlog",
        "ibm_svc_host",
        "ibm_svc_license",
        "ibm_svc_mdisk",
        "ibm_svc_mdiskgrp",
        "ibm_svc_node",
        "ibm_svc_nodestats",
        "ibm_svc_nodestats_diskio",
        "ibm_svc_nodestats_iops",
        "ibm_svc_nodestats_disk_latency",
        "ibm_svc_nodestats_cpu_util",
        "ibm_svc_nodestats_cache",
        "ibm_svc_portfc",
        "ibm_svc_portsas",
        "ibm_svc_system",
        "ibm_tl_changer_devices",
        "ibm_tl_media_access_devices",
        "ibm_xraid_pdisks",
        "icom_repeater_ps_volt",
        "icom_repeater_pll_volt",
        "icom_repeater_temp",
        "icom_repeater",
        "infoblox_dhcp_stats",
        "infoblox_dns_stats",
        "infoblox_grid_status",
        "infoblox_replication_status",
        "informix_dbspaces",
        "informix_locks",
        "informix_logusage",
        "informix_sessions",
        "informix_status",
        "informix_tabextents",
        "innovaphone_channels",
        "innovaphone_cpu",
        "innovaphone_licenses",
        "innovaphone_mem",
        "innovaphone_priports_l1",
        "innovaphone_priports_l2",
        "innovaphone_temp",
        "intel_true_scale_chassis_temp",
        "intel_true_scale_fans",
        "intel_true_scale_psus",
        "intel_true_scale_sensors_temp",
        "ipr400_in_voltage",
        "ipr400_temp",
        "iptables",
        "ispro_sensors_digital",
        "ispro_sensors_humid",
        "ispro_sensors_temp",
        "janitza_umg",
        "janitza_umg_freq",
        "janitza_umg_temp",
        "jar_signature",
        "jira_custom_svc",
        "jira_workflow",
        "jolokia_generic_string",
        "jolokia_generic_rate",
        "jolokia_generic",
        "jolokia_info",
        "jolokia_jvm_garbagecollectors",
        "jolokia_jvm_memory",
        "jolokia_jvm_memory_pools",
        "jolokia_jvm_runtime",
        "jolokia_jvm_threading",
        "jolokia_jvm_threading_pool",
        "jolokia_metrics",
        "jolokia_metrics_serv_req",
        "jolokia_metrics_app_state",
        "jolokia_metrics_app_sess",
        "jolokia_metrics_requests",
        "jolokia_metrics_bea_queue",
        "jolokia_metrics_bea_requests",
        "jolokia_metrics_bea_threads",
        "jolokia_metrics_bea_sess",
        "jolokia_metrics_cache_hits",
        "jolokia_metrics_in_memory",
        "jolokia_metrics_on_disk",
        "jolokia_metrics_off_heap",
        "jolokia_metrics_writer",
        "juniper_alarm",
        "juniper_bgp_state",
        "juniper_fru",
        "juniper_fru_fan",
        "juniper_mem",
        "juniper_screenos_cpu",
        "juniper_screenos_fan",
        "juniper_screenos_mem",
        "juniper_screenos_temp",
        "juniper_screenos_vpn",
        "juniper_temp",
        "juniper_trpz_flash",
        "juniper_trpz_info",
        "juniper_trpz_mem",
        "juniper_trpz_power",
        "keepalived",
        "kemp_loadmaster_ha",
        "kentix_amp_sensors",
        "kentix_amp_sensors_humidity",
        "kentix_amp_sensors_smoke",
        "kentix_amp_sensors_leakage",
        "kentix_co",
        "kentix_dewpoint",
        "kentix_humidity",
        "kentix_motion",
        "kentix_temp",
        "kernel",
        "kernel_performance",
        "knuerr_rms_humidity",
        "knuerr_rms_temp",
        "knuerr_sensors",
        "lgp_info",
        "lgp_pdu_aux",
        "lgp_pdu_info",
        "libelle_business_shadow",
        "libelle_business_shadow_info",
        "libelle_business_shadow_status",
        "libelle_business_shadow_process",
        "libelle_business_shadow_archive_dir",
        "logins",
        "lvm_lvs",
        "lvm_vgs",
        "mailman_lists",
        "mbg_lantime_ng_fan",
        "mbg_lantime_ng_power",
        "mbg_lantime_ng_refclock_gps",
        "mbg_lantime_ng_refclock",
        "mbg_lantime_ng_state",
        "mbg_lantime_ng_temp",
        "mbg_lantime_refclock",
        "mbg_lantime_state",
        "mcafee_emailgateway_agent",
        "mcafee_emailgateway_av_authentium",
        "mcafee_emailgateway_av_mcafee",
        "mcafee_emailgateway_bridge",
        "mcafee_emailgateway_entities",
        "mcafee_emailgateway_smtp",
        "mcafee_emailgateway_spam_mcafee",
        "md",
        "megaraid_bbu",
        "mem_linux",
        "mem_vmalloc",
        "mikrotik_signal",
        "mkbackup",
        "mkbackup_site",
        "mkeventd_status",
        "mongodb_cluster",
        "mongodb_cluster_collections",
        "mongodb_cluster_balancer",
        "mongodb_collections",
        "mongodb_connections",
        "mongodb_counters",
        "mongodb_flushing",
        "mongodb_instance",
        "mongodb_locks",
        "mongodb_mem",
        "mongodb_replica_set",
        "mongodb_replica_set_election",
        "mongodb_replication_info",
        "moxa_iologik_register",
        "mq_queues",
        "msexch_activesync",
        "msexch_autodiscovery",
        "msexch_availability",
        "msexch_dag",
        "msexch_dag_dbcopy",
        "msexch_dag_contentindex",
        "msexch_dag_copyqueue",
        "msexch_owa",
        "msexch_replhealth",
        "msoffice_licenses",
        "msoffice_serviceplans",
        "mssql_connections",
        "mssql_instance",
        "mysql",
        "mysql_sessions",
        "mysql_innodb_io",
        "mysql_connections",
        "mysql_galerasync",
        "mysql_galeradonor",
        "mysql_galerastartup",
        "mysql_galerasize",
        "mysql_galerastatus",
        "mysql_ping",
        "netapp_cluster",
        "netapp_cpu",
        "netapp_fcpio",
        "netapp_vfiler",
        "netctr",
        "netctr_combined",
        "netextreme_cpu_util",
        "netextreme_fan",
        "netextreme_psu",
        "netextreme_psu_in",
        "netextreme_psu_out",
        "netextreme_temp",
        "netgear_fans",
        "netgear_powersupplies",
        "netgear_temp",
        "netscaler_cpu",
        "netscaler_dnsrates",
        "netscaler_ha",
        "netscaler_health",
        "netscaler_health_fan",
        "netscaler_health_temp",
        "netscaler_health_psu",
        "netscaler_mem",
        "netstat",
        "nfsexports",
        "nginx_status",
        "nimble_latency",
        "nimble_latency_write",
        "nimble_volumes",
        "nullmailer_mailq",
        "nvidia",
        "nvidia_temp",
        "nvidia_temp_core",
        "nvidia_errors",
        "omd_apache",
        "openbsd_sensors",
        "openbsd_sensors_fan",
        "openbsd_sensors_voltage",
        "openbsd_sensors_powersupply",
        "openbsd_sensors_indicator",
        "openbsd_sensors_drive",
        "openhardwaremonitor",
        "openhardwaremonitor_temperature",
        "openhardwaremonitor_power",
        "openhardwaremonitor_fan",
        "openhardwaremonitor_smart",
        "openvpn_clients",
        "oracle_crs_version",
        "oracle_crs_voting",
        "oracle_dataguard_stats",
        "oracle_diva_csm",
        "oracle_diva_csm_drive",
        "oracle_diva_csm_actor",
        "oracle_diva_csm_archive",
        "oracle_diva_csm_objects",
        "oracle_diva_csm_tapes",
        "oracle_jobs",
        "oracle_locks",
        "oracle_logswitches",
        "oracle_longactivesessions",
        "oracle_recovery_area",
        "oracle_recovery_status",
        "oracle_sessions",
        "oracle_undostat",
        "oracle_version",
        "orion_backup",
        "orion_batterytest",
        "orion_system",
        "orion_system_charging",
        "orion_system_dc",
        "packeteer_fan_status",
        "packeteer_ps_status",
        "palo_alto_sessions",
        "pandacom_10gm_temp",
        "pandacom_fan",
        "pandacom_fc_temp",
        "pandacom_psu",
        "pandacom_sys_temp",
        "papouch_th2e_sensors",
        "papouch_th2e_sensors_dewpoint",
        "papouch_th2e_sensors_humidity",
        "perle_chassis",
        "perle_chassis_temp",
        "perle_chassis_slots",
        "perle_modules_cm1000",
        "perle_modules_cm1110",
        "perle_modules_mgt",
        "perle_psmu",
        "perle_psmu_fan",
        "pfsense_status",
        "plesk_backups",
        "plesk_domains",
        "poseidon_inputs",
        "poseidon_temp",
        "postfix_mailq",
        "postgres_bloat",
        "postgres_conn_time",
        "postgres_connections",
        "postgres_locks",
        "postgres_sessions",
        "postgres_stat_database",
        "postgres_stat_database_size",
        "printer_supply_ricoh",
        "prometheus_custom",
        "pulse_secure_cpu_util",
        "pulse_secure_disk_util",
        "pulse_secure_log_util",
        "pulse_secure_mem_util",
        "pulse_secure_temp",
        "pvecm_nodes",
        "pvecm_status",
        "qlogic_fcport",
        "qlogic_sanbox",
        "qlogic_sanbox_temp",
        "qlogic_sanbox_psu",
        "qlogic_sanbox_fabric_element",
        "qmail_stats",
        "qnap_disks",
        "qnap_fans",
        "qnap_hdd_temp",
        "quanta_fan",
        "quanta_temperature",
        "quanta_voltage",
        "ra32e_power",
        "ra32e_sensors",
        "ra32e_sensors_humidity",
        "ra32e_sensors_voltage",
        "ra32e_sensors_power",
        "ra32e_switch",
        "rabbitmq_cluster",
        "rabbitmq_cluster_messages",
        "rabbitmq_cluster_stats",
        "rabbitmq_nodes",
        "rabbitmq_nodes_filedesc",
        "rabbitmq_nodes_sockets",
        "rabbitmq_nodes_mem",
        "rabbitmq_nodes_uptime",
        "rabbitmq_nodes_gc",
        "rabbitmq_queues",
        "rabbitmq_vhosts",
        "raritan_emx",
        "raritan_emx_fan",
        "raritan_emx_binary",
        "raritan_emx_sensors",
        "raritan_emx_sensors_temp",
        "raritan_emx_sensors_airflow",
        "raritan_emx_sensors_humidity",
        "raritan_emx_sensors_pressure",
        "raritan_pdu_inlet",
        "raritan_pdu_inlet_summary",
        "raritan_pdu_ocprot",
        "raritan_pdu_outletcount",
        "raritan_pdu_plugs",
        "raritan_px2_sensors",
        "raritan_px2_sensors_airflow",
        "raritan_px2_sensors_humidity",
        "raritan_px2_sensors_pressure",
        "raritan_px_outlets",
        "raritan_px_sensors",
        "raritan_px_sensors_humidity",
        "raritan_px_sensors_binary",
        "rds_licenses",
        "rms200_temp",
        "rstcli",
        "rstcli_pdisks",
        "safenet_hsm_events",
        "safenet_hsm",
        "safenet_ntls_connrate",
        "safenet_ntls_expiration",
        "safenet_ntls_links",
        "safenet_ntls_clients",
        "safenet_ntls",
        "salesforce_instances",
        "sansymphony_alerts",
        "sansymphony_ports",
        "sansymphony_serverstatus",
        "sansymphony_virtualdiskstatus",
        "sap_hana_connect",
        "sap_hana_ess_migration",
        "sap_state",
        "saprouter_cert",
        "scaleio_devices",
        "scaleio_mdm",
        "scaleio_pd",
        "scaleio_pd_status",
        "scaleio_sds",
        "scaleio_sds_status",
        "scaleio_system",
        "security_master",
        "security_master_humidity",
        "security_master_temp",
        "seh_ports",
        "sensatronics_temp",
        "sentry_pdu_systempower",
        "siemens_plc",
        "siemens_plc_temp",
        "siemens_plc_flag",
        "siemens_plc_duration",
        "siemens_plc_counter",
        "siemens_plc_info",
        "siemens_plc_cpu_state",
        "silverpeak_VX6000",
        "skype",
        "skype_mcu",
        "skype_conferencing",
        "skype_sip_stack",
        "skype_mediation_server",
        "skype_edge_auth",
        "skype_edge",
        "skype_data_proxy",
        "skype_xmpp_proxy",
        "skype_mobile",
        "smart_temp",
        "sni_octopuse_cpu",
        "sni_octopuse_status",
        "sni_octopuse_trunks",
        "solaris_fmadm",
        "solaris_multipath",
        "solaris_prtdiag_status",
        "sophos",
        "sophos_cpu",
        "sophos_disk",
        "sophos_memory",
        "sophos_messages",
        "steelhead_connections",
        "steelhead_peers",
        "steelhead_status",
        "storcli_pdisks",
        "storeonce4x_alerts",
        "storeonce4x_d2d_services",
        "stormshield_cluster",
        "stormshield_cpu_temp",
        "stormshield_disk",
        "stormshield_info",
        "stormshield_packets",
        "stormshield_policy",
        "stormshield_route",
        "stormshield_updates",
        "strem1_sensors",
        "stulz_alerts",
        "stulz_humidity",
        "stulz_powerstate",
        "stulz_pump",
        "stulz_temp",
        "supermicro",
        "supermicro_sensors",
        "supermicro_smart",
        "superstack3_sensors",
        "suseconnect",
        "sylo",
        "sym_brightmail_queues",
        "symantec_av_progstate",
        "symantec_av_quarantine",
        "symantec_av_updates",
        "systemtime",
        "teracom_tcw241_analog",
        "teracom_tcw241_digital",
        "tinkerforge",
        "tinkerforge_temperature",
        "tinkerforge_ambient",
        "tinkerforge_humidity",
        "tinkerforge_motion",
        "tplink_cpu",
        "tplink_mem",
        "tplink_poe_summary",
        "tsm_drives",
        "tsm_paths",
        "tsm_scratch",
        "tsm_sessions",
        "tsm_storagepools",
        "ucd_disk",
        "ucd_mem",
        "ucd_processes",
        "ucs_bladecenter_fans",
        "ucs_bladecenter_fans_temp",
        "ucs_bladecenter_faultinst",
        "ucs_bladecenter_psu",
        "ucs_bladecenter_psu_switch_power",
        "ucs_bladecenter_psu_chassis_temp",
        "ucs_bladecenter_topsystem",
        "ucs_c_rack_server_fans",
        "ucs_c_rack_server_faultinst",
        "ucs_c_rack_server_health",
        "ucs_c_rack_server_led",
        "ucs_c_rack_server_power",
        "ucs_c_rack_server_psu",
        "ucs_c_rack_server_psu_voltage",
        "ucs_c_rack_server_temp",
        "ucs_c_rack_server_topsystem",
        "unitrends_backup",
        "unitrends_replication",
        "ups_bat_temp",
        "ups_cps_battery_temp",
        "ups_cps_battery",
        "ups_cps_inphase",
        "ups_cps_outphase",
        "ups_eaton_enviroment",
        "ups_in_freq",
        "ups_in_voltage",
        "ups_modulys_alarms",
        "ups_modulys_inphase",
        "ups_modulys_outphase",
        "ups_out_voltage",
        "ups_socomec_capacity",
        "ups_socomec_in_voltage",
        "ups_socomec_out_source",
        "ups_socomec_out_voltage",
        "ups_socomec_outphase",
        "varnish",
        "varnish_cache",
        "varnish_client",
        "varnish_backend",
        "varnish_fetch",
        "varnish_esi",
        "varnish_objects",
        "varnish_worker",
        "varnish_cache_hit_ratio",
        "varnish_backend_success_ratio",
        "varnish_worker_thread_ratio",
        "vbox_guest",
        "veeam_client",
        "veeam_tapejobs",
        "viprinet_firmware",
        "viprinet_mem",
        "viprinet_power",
        "viprinet_router",
        "viprinet_serial",
        "viprinet_temp",
        "vms_cpu",
        "vms_queuejobs",
        "vms_system",
        "vms_system_ios",
        "vms_system_procs",
        "vms_users",
        "vnx_version",
        "vutlan_ems_humidity",
        "vutlan_ems_leakage",
        "vutlan_ems_temp",
        "vxvm_objstatus",
        "wagner_titanus_topsense",
        "wagner_titanus_topsense_info",
        "wagner_titanus_topsense_overall_status",
        "wagner_titanus_topsense_alarm",
        "wagner_titanus_topsense_smoke",
        "wagner_titanus_topsense_chamber_deviation",
        "wagner_titanus_topsense_airflow_deviation",
        "wagner_titanus_topsense_temp",
        "watchdog_sensors",
        "watchdog_sensors_temp",
        "watchdog_sensors_humidity",
        "watchdog_sensors_dew",
        "win_license",
        "win_netstat",
        "win_printers",
        "windows_broadcom_bonding",
        "windows_multipath",
        "winperf",
        "winperf_cpuusage",
        "winperf_diskstat",
        "winperf_mem",
        "winperf_ts_sessions",
        "wmi_webservices",
        "wmic_process",
        "wut_webtherm",
        "wut_webtherm_pressure",
        "wut_webtherm_humidity",
    }
    current_legacy_checks = {lcd.name for lcd in fix_plugin_legacy.check_info.values()}

    new_legacy_checks = current_legacy_checks - expected_legacy_checks
    assert not new_legacy_checks, (
        "Found these new legacy checks: %s. Implementing new legacy "
        "checks is forbidden, please use the new API." % ", ".join(sorted(new_legacy_checks))
    )

    vanished_legacy_checks = expected_legacy_checks - current_legacy_checks
    assert not vanished_legacy_checks, (
        "The following legacy checks have vanished: %s. Please "
        "remove them from 'allowed_legacy_checks' in this unit "
        "test." % ", ".join(sorted(vanished_legacy_checks))
    )
