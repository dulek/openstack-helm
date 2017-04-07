
# Copyright 2017 The Openstack-Helm Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

{{ include "cinder.conf.cinder_values_skeleton" .Values.conf.cinder | trunc 0 }}
{{ include "cinder.conf.cinder" .Values.conf.cinder }}


{{- define "cinder.conf.cinder_values_skeleton" -}}

{{- if not .default -}}{{- set . "default" dict -}}{{- end -}}
{{- if not .default.cinder -}}{{- set .default "cinder" dict -}}{{- end -}}
{{- if not .default.oslo -}}{{- set .default "oslo" dict -}}{{- end -}}
{{- if not .default.oslo.config -}}{{- set .default.oslo "config" dict -}}{{- end -}}
{{- if not .default.oslo.log -}}{{- set .default.oslo "log" dict -}}{{- end -}}
{{- if not .default.oslo.messaging -}}{{- set .default.oslo "messaging" dict -}}{{- end -}}
{{- if not .default.oslo.service -}}{{- set .default.oslo "service" dict -}}{{- end -}}
{{- if not .default.oslo.service.periodic_task -}}{{- set .default.oslo.service "periodic_task" dict -}}{{- end -}}
{{- if not .default.oslo.service.service -}}{{- set .default.oslo.service "service" dict -}}{{- end -}}
{{- if not .default.oslo.service.wsgi -}}{{- set .default.oslo.service "wsgi" dict -}}{{- end -}}
{{- if not .backend -}}{{- set . "backend" dict -}}{{- end -}}
{{- if not .backend.cinder -}}{{- set .backend "cinder" dict -}}{{- end -}}
{{- if not .brcd_fabric_example -}}{{- set . "brcd_fabric_example" dict -}}{{- end -}}
{{- if not .brcd_fabric_example.cinder -}}{{- set .brcd_fabric_example "cinder" dict -}}{{- end -}}
{{- if not .cisco_fabric_example -}}{{- set . "cisco_fabric_example" dict -}}{{- end -}}
{{- if not .cisco_fabric_example.cinder -}}{{- set .cisco_fabric_example "cinder" dict -}}{{- end -}}
{{- if not .coordination -}}{{- set . "coordination" dict -}}{{- end -}}
{{- if not .coordination.cinder -}}{{- set .coordination "cinder" dict -}}{{- end -}}
{{- if not .fc_zone_manager -}}{{- set . "fc_zone_manager" dict -}}{{- end -}}
{{- if not .fc_zone_manager.cinder -}}{{- set .fc_zone_manager "cinder" dict -}}{{- end -}}
{{- if not .key_manager -}}{{- set . "key_manager" dict -}}{{- end -}}
{{- if not .key_manager.cinder -}}{{- set .key_manager "cinder" dict -}}{{- end -}}
{{- if not .barbican -}}{{- set . "barbican" dict -}}{{- end -}}
{{- if not .barbican.castellan -}}{{- set .barbican "castellan" dict -}}{{- end -}}
{{- if not .barbican.castellan.config -}}{{- set .barbican.castellan "config" dict -}}{{- end -}}
{{- if not .cors -}}{{- set . "cors" dict -}}{{- end -}}
{{- if not .cors.oslo -}}{{- set .cors "oslo" dict -}}{{- end -}}
{{- if not .cors.oslo.middleware -}}{{- set .cors.oslo "middleware" dict -}}{{- end -}}
{{- if not .cors.subdomain -}}{{- set .cors "subdomain" dict -}}{{- end -}}
{{- if not .cors.subdomain.oslo -}}{{- set .cors.subdomain "oslo" dict -}}{{- end -}}
{{- if not .cors.subdomain.oslo.middleware -}}{{- set .cors.subdomain.oslo "middleware" dict -}}{{- end -}}
{{- if not .database -}}{{- set . "database" dict -}}{{- end -}}
{{- if not .database.oslo -}}{{- set .database "oslo" dict -}}{{- end -}}
{{- if not .database.oslo.db -}}{{- set .database.oslo "db" dict -}}{{- end -}}
{{- if not .key_manager.castellan -}}{{- set .key_manager "castellan" dict -}}{{- end -}}
{{- if not .key_manager.castellan.config -}}{{- set .key_manager.castellan "config" dict -}}{{- end -}}
{{- if not .keystone_authtoken -}}{{- set . "keystone_authtoken" dict -}}{{- end -}}
{{- if not .keystone_authtoken.keystonemiddleware -}}{{- set .keystone_authtoken "keystonemiddleware" dict -}}{{- end -}}
{{- if not .keystone_authtoken.keystonemiddleware.auth_token -}}{{- set .keystone_authtoken.keystonemiddleware "auth_token" dict -}}{{- end -}}
{{- if not .matchmaker_redis -}}{{- set . "matchmaker_redis" dict -}}{{- end -}}
{{- if not .matchmaker_redis.oslo -}}{{- set .matchmaker_redis "oslo" dict -}}{{- end -}}
{{- if not .matchmaker_redis.oslo.messaging -}}{{- set .matchmaker_redis.oslo "messaging" dict -}}{{- end -}}
{{- if not .oslo_concurrency -}}{{- set . "oslo_concurrency" dict -}}{{- end -}}
{{- if not .oslo_concurrency.oslo -}}{{- set .oslo_concurrency "oslo" dict -}}{{- end -}}
{{- if not .oslo_concurrency.oslo.concurrency -}}{{- set .oslo_concurrency.oslo "concurrency" dict -}}{{- end -}}
{{- if not .oslo_messaging_amqp -}}{{- set . "oslo_messaging_amqp" dict -}}{{- end -}}
{{- if not .oslo_messaging_amqp.oslo -}}{{- set .oslo_messaging_amqp "oslo" dict -}}{{- end -}}
{{- if not .oslo_messaging_amqp.oslo.messaging -}}{{- set .oslo_messaging_amqp.oslo "messaging" dict -}}{{- end -}}
{{- if not .oslo_messaging_notifications -}}{{- set . "oslo_messaging_notifications" dict -}}{{- end -}}
{{- if not .oslo_messaging_notifications.oslo -}}{{- set .oslo_messaging_notifications "oslo" dict -}}{{- end -}}
{{- if not .oslo_messaging_notifications.oslo.messaging -}}{{- set .oslo_messaging_notifications.oslo "messaging" dict -}}{{- end -}}
{{- if not .oslo_messaging_rabbit -}}{{- set . "oslo_messaging_rabbit" dict -}}{{- end -}}
{{- if not .oslo_messaging_rabbit.oslo -}}{{- set .oslo_messaging_rabbit "oslo" dict -}}{{- end -}}
{{- if not .oslo_messaging_rabbit.oslo.messaging -}}{{- set .oslo_messaging_rabbit.oslo "messaging" dict -}}{{- end -}}
{{- if not .oslo_messaging_zmq -}}{{- set . "oslo_messaging_zmq" dict -}}{{- end -}}
{{- if not .oslo_messaging_zmq.oslo -}}{{- set .oslo_messaging_zmq "oslo" dict -}}{{- end -}}
{{- if not .oslo_messaging_zmq.oslo.messaging -}}{{- set .oslo_messaging_zmq.oslo "messaging" dict -}}{{- end -}}
{{- if not .oslo_middleware -}}{{- set . "oslo_middleware" dict -}}{{- end -}}
{{- if not .oslo_middleware.oslo -}}{{- set .oslo_middleware "oslo" dict -}}{{- end -}}
{{- if not .oslo_middleware.oslo.middleware -}}{{- set .oslo_middleware.oslo "middleware" dict -}}{{- end -}}
{{- if not .oslo_policy -}}{{- set . "oslo_policy" dict -}}{{- end -}}
{{- if not .oslo_policy.oslo -}}{{- set .oslo_policy "oslo" dict -}}{{- end -}}
{{- if not .oslo_policy.oslo.policy -}}{{- set .oslo_policy.oslo "policy" dict -}}{{- end -}}
{{- if not .oslo_reports -}}{{- set . "oslo_reports" dict -}}{{- end -}}
{{- if not .oslo_reports.oslo -}}{{- set .oslo_reports "oslo" dict -}}{{- end -}}
{{- if not .oslo_reports.oslo.reports -}}{{- set .oslo_reports.oslo "reports" dict -}}{{- end -}}
{{- if not .oslo_versionedobjects -}}{{- set . "oslo_versionedobjects" dict -}}{{- end -}}
{{- if not .oslo_versionedobjects.oslo -}}{{- set .oslo_versionedobjects "oslo" dict -}}{{- end -}}
{{- if not .oslo_versionedobjects.oslo.versionedobjects -}}{{- set .oslo_versionedobjects.oslo "versionedobjects" dict -}}{{- end -}}
{{- if not .ssl -}}{{- set . "ssl" dict -}}{{- end -}}
{{- if not .ssl.oslo -}}{{- set .ssl "oslo" dict -}}{{- end -}}
{{- if not .ssl.oslo.service -}}{{- set .ssl.oslo "service" dict -}}{{- end -}}
{{- if not .ssl.oslo.service.sslutils -}}{{- set .ssl.oslo.service "sslutils" dict -}}{{- end -}}

{{- end -}}


{{- define "cinder.conf.cinder" -}}

[DEFAULT]

#
# From cinder
#

# Backup metadata version to be used when backing up volume metadata.
# If this number is bumped, make sure the service doing the restore
# supports the new version. (integer value)
# from .default.cinder.backup_metadata_version
{{ if not .default.cinder.backup_metadata_version }}#{{ end }}backup_metadata_version = {{ .default.cinder.backup_metadata_version | default "2" }}

# The number of chunks or objects, for which one Ceilometer
# notification will be sent (integer value)
# from .default.cinder.backup_object_number_per_notification
{{ if not .default.cinder.backup_object_number_per_notification }}#{{ end }}backup_object_number_per_notification = {{ .default.cinder.backup_object_number_per_notification | default "10" }}

# Interval, in seconds, between two progress notifications reporting
# the backup status (integer value)
# from .default.cinder.backup_timer_interval
{{ if not .default.cinder.backup_timer_interval }}#{{ end }}backup_timer_interval = {{ .default.cinder.backup_timer_interval | default "120" }}

# Name of this cluster.  Used to group volume hosts that share the
# same backend configurations to work in HA Active-Active mode.
# Active-Active is not yet supported. (string value)
# from .default.cinder.cluster
{{ if not .default.cinder.cluster }}#{{ end }}cluster = {{ .default.cinder.cluster | default "<None>" }}

# The maximum number of items that a collection resource returns in a
# single response (integer value)
# from .default.cinder.osapi_max_limit
{{ if not .default.cinder.osapi_max_limit }}#{{ end }}osapi_max_limit = {{ .default.cinder.osapi_max_limit | default "1000" }}

# Base URL that will be presented to users in links to the OpenStack
# Volume API (string value)
# Deprecated group/name - [DEFAULT]/osapi_compute_link_prefix
# from .default.cinder.osapi_volume_base_URL
{{ if not .default.cinder.osapi_volume_base_URL }}#{{ end }}osapi_volume_base_URL = {{ .default.cinder.osapi_volume_base_URL | default "<None>" }}

# Volume filter options which non-admin user could use to query
# volumes. Default values are: ['name', 'status', 'metadata',
# 'availability_zone' ,'bootable', 'group_id'] (list value)
# from .default.cinder.query_volume_filters
{{ if not .default.cinder.query_volume_filters }}#{{ end }}query_volume_filters = {{ .default.cinder.query_volume_filters | default "name,status,metadata,availability_zone,bootable,group_id" }}

# Ceph configuration file to use. (string value)
# from .default.cinder.backup_ceph_conf
{{ if not .default.cinder.backup_ceph_conf }}#{{ end }}backup_ceph_conf = {{ .default.cinder.backup_ceph_conf | default "/etc/ceph/ceph.conf" }}

# The Ceph user to connect with. Default here is to use the same user
# as for Cinder volumes. If not using cephx this should be set to
# None. (string value)
# from .default.cinder.backup_ceph_user
{{ if not .default.cinder.backup_ceph_user }}#{{ end }}backup_ceph_user = {{ .default.cinder.backup_ceph_user | default "cinder" }}

# The chunk size, in bytes, that a backup is broken into before
# transfer to the Ceph object store. (integer value)
# from .default.cinder.backup_ceph_chunk_size
{{ if not .default.cinder.backup_ceph_chunk_size }}#{{ end }}backup_ceph_chunk_size = {{ .default.cinder.backup_ceph_chunk_size | default "134217728" }}

# The Ceph pool where volume backups are stored. (string value)
# from .default.cinder.backup_ceph_pool
{{ if not .default.cinder.backup_ceph_pool }}#{{ end }}backup_ceph_pool = {{ .default.cinder.backup_ceph_pool | default "backups" }}

# RBD stripe unit to use when creating a backup image. (integer value)
# from .default.cinder.backup_ceph_stripe_unit
{{ if not .default.cinder.backup_ceph_stripe_unit }}#{{ end }}backup_ceph_stripe_unit = {{ .default.cinder.backup_ceph_stripe_unit | default "0" }}

# RBD stripe count to use when creating a backup image. (integer
# value)
# from .default.cinder.backup_ceph_stripe_count
{{ if not .default.cinder.backup_ceph_stripe_count }}#{{ end }}backup_ceph_stripe_count = {{ .default.cinder.backup_ceph_stripe_count | default "0" }}

# If True, always discard excess bytes when restoring volumes i.e. pad
# with zeroes. (boolean value)
# from .default.cinder.restore_discard_excess_bytes
{{ if not .default.cinder.restore_discard_excess_bytes }}#{{ end }}restore_discard_excess_bytes = {{ .default.cinder.restore_discard_excess_bytes | default "true" }}

# Compression algorithm (None to disable) (string value)
# from .default.cinder.backup_compression_algorithm
{{ if not .default.cinder.backup_compression_algorithm }}#{{ end }}backup_compression_algorithm = {{ .default.cinder.backup_compression_algorithm | default "zlib" }}

# Sets the value of TCP_KEEPALIVE (True/False) for each server socket.
# (boolean value)
# from .default.cinder.tcp_keepalive
{{ if not .default.cinder.tcp_keepalive }}#{{ end }}tcp_keepalive = {{ .default.cinder.tcp_keepalive | default "true" }}

# Sets the value of TCP_KEEPINTVL in seconds for each server socket.
# Not supported on OS X. (integer value)
# from .default.cinder.tcp_keepalive_interval
{{ if not .default.cinder.tcp_keepalive_interval }}#{{ end }}tcp_keepalive_interval = {{ .default.cinder.tcp_keepalive_interval | default "<None>" }}

# Sets the value of TCP_KEEPCNT for each server socket. Not supported
# on OS X. (integer value)
# from .default.cinder.tcp_keepalive_count
{{ if not .default.cinder.tcp_keepalive_count }}#{{ end }}tcp_keepalive_count = {{ .default.cinder.tcp_keepalive_count | default "<None>" }}

# Option to enable strict host key checking.  When set to "True"
# Cinder will only connect to systems with a host key present in the
# configured "ssh_hosts_key_file".  When set to "False" the host key
# will be saved upon first connection and used for subsequent
# connections.  Default=False (boolean value)
# from .default.cinder.strict_ssh_host_key_policy
{{ if not .default.cinder.strict_ssh_host_key_policy }}#{{ end }}strict_ssh_host_key_policy = {{ .default.cinder.strict_ssh_host_key_policy | default "false" }}

# File containing SSH host keys for the systems with which Cinder
# needs to communicate.  OPTIONAL: Default=$state_path/ssh_known_hosts
# (string value)
# from .default.cinder.ssh_hosts_key_file
{{ if not .default.cinder.ssh_hosts_key_file }}#{{ end }}ssh_hosts_key_file = {{ .default.cinder.ssh_hosts_key_file | default "$state_path/ssh_known_hosts" }}

# Base dir containing mount point for gluster share. (string value)
# from .default.cinder.glusterfs_backup_mount_point
{{ if not .default.cinder.glusterfs_backup_mount_point }}#{{ end }}glusterfs_backup_mount_point = {{ .default.cinder.glusterfs_backup_mount_point | default "$state_path/backup_mount" }}

# GlusterFS share in <hostname|ipv4addr|ipv6addr>:<gluster_vol_name>
# format. Eg: 1.2.3.4:backup_vol (string value)
# from .default.cinder.glusterfs_backup_share
{{ if not .default.cinder.glusterfs_backup_share }}#{{ end }}glusterfs_backup_share = {{ .default.cinder.glusterfs_backup_share | default "<None>" }}

# Volume prefix for the backup id when backing up to TSM (string
# value)
# from .default.cinder.backup_tsm_volume_prefix
{{ if not .default.cinder.backup_tsm_volume_prefix }}#{{ end }}backup_tsm_volume_prefix = {{ .default.cinder.backup_tsm_volume_prefix | default "backup" }}

# TSM password for the running username (string value)
# from .default.cinder.backup_tsm_password
{{ if not .default.cinder.backup_tsm_password }}#{{ end }}backup_tsm_password = {{ .default.cinder.backup_tsm_password | default "password" }}

# Enable or Disable compression for backups (boolean value)
# from .default.cinder.backup_tsm_compression
{{ if not .default.cinder.backup_tsm_compression }}#{{ end }}backup_tsm_compression = {{ .default.cinder.backup_tsm_compression | default "true" }}

# Make exception message format errors fatal. (boolean value)
# from .default.cinder.fatal_exception_format_errors
{{ if not .default.cinder.fatal_exception_format_errors }}#{{ end }}fatal_exception_format_errors = {{ .default.cinder.fatal_exception_format_errors | default "false" }}

# Top-level directory for maintaining cinder's state (string value)
# Deprecated group/name - [DEFAULT]/pybasedir
# from .default.cinder.state_path
{{ if not .default.cinder.state_path }}#{{ end }}state_path = {{ .default.cinder.state_path | default "/var/lib/cinder" }}

# IP address of this host (string value)
# from .default.cinder.my_ip
{{ if not .default.cinder.my_ip }}#{{ end }}my_ip = {{ .default.cinder.my_ip | default "10.102.86.147" }}

# A list of the URLs of glance API servers available to cinder
# ([http[s]://][hostname|ip]:port). If protocol is not specified it
# defaults to http. (list value)
# from .default.cinder.glance_api_servers
{{ if not .default.cinder.glance_api_servers }}#{{ end }}glance_api_servers = {{ .default.cinder.glance_api_servers | default "<None>" }}

# Version of the glance API to use (integer value)
# from .default.cinder.glance_api_version
{{ if not .default.cinder.glance_api_version }}#{{ end }}glance_api_version = {{ .default.cinder.glance_api_version | default "1" }}

# Number retries when downloading an image from glance (integer value)
# Minimum value: 0
# from .default.cinder.glance_num_retries
{{ if not .default.cinder.glance_num_retries }}#{{ end }}glance_num_retries = {{ .default.cinder.glance_num_retries | default "0" }}

# Allow to perform insecure SSL (https) requests to glance (https will
# be used but cert validation will not be performed). (boolean value)
# from .default.cinder.glance_api_insecure
{{ if not .default.cinder.glance_api_insecure }}#{{ end }}glance_api_insecure = {{ .default.cinder.glance_api_insecure | default "false" }}

# Enables or disables negotiation of SSL layer compression. In some
# cases disabling compression can improve data throughput, such as
# when high network bandwidth is available and you use compressed
# image formats like qcow2. (boolean value)
# from .default.cinder.glance_api_ssl_compression
{{ if not .default.cinder.glance_api_ssl_compression }}#{{ end }}glance_api_ssl_compression = {{ .default.cinder.glance_api_ssl_compression | default "false" }}

# Location of ca certificates file to use for glance client requests.
# (string value)
# from .default.cinder.glance_ca_certificates_file
{{ if not .default.cinder.glance_ca_certificates_file }}#{{ end }}glance_ca_certificates_file = {{ .default.cinder.glance_ca_certificates_file | default "<None>" }}

# http/https timeout value for glance operations. If no value (None)
# is supplied here, the glanceclient default value is used. (integer
# value)
# from .default.cinder.glance_request_timeout
{{ if not .default.cinder.glance_request_timeout }}#{{ end }}glance_request_timeout = {{ .default.cinder.glance_request_timeout | default "<None>" }}

# DEPRECATED: Deploy v1 of the Cinder API. (boolean value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# from .default.cinder.enable_v1_api
{{ if not .default.cinder.enable_v1_api }}#{{ end }}enable_v1_api = {{ .default.cinder.enable_v1_api | default "true" }}

# DEPRECATED: Deploy v2 of the Cinder API. (boolean value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# from .default.cinder.enable_v2_api
{{ if not .default.cinder.enable_v2_api }}#{{ end }}enable_v2_api = {{ .default.cinder.enable_v2_api | default "true" }}

# Deploy v3 of the Cinder API. (boolean value)
# from .default.cinder.enable_v3_api
{{ if not .default.cinder.enable_v3_api }}#{{ end }}enable_v3_api = {{ .default.cinder.enable_v3_api | default "true" }}

# Enables or disables rate limit of the API. (boolean value)
# from .default.cinder.api_rate_limit
{{ if not .default.cinder.api_rate_limit }}#{{ end }}api_rate_limit = {{ .default.cinder.api_rate_limit | default "true" }}

# Specify list of extensions to load when using osapi_volume_extension
# option with cinder.api.contrib.select_extensions (list value)
# from .default.cinder.osapi_volume_ext_list
{{ if not .default.cinder.osapi_volume_ext_list }}#{{ end }}osapi_volume_ext_list = {{ .default.cinder.osapi_volume_ext_list | default "" }}

# osapi volume extension to load (multi valued)
# from .default.cinder.osapi_volume_extension (multiopt)
{{ if not .default.cinder.osapi_volume_extension }}#osapi_volume_extension = {{ .default.cinder.osapi_volume_extension | default "cinder.api.contrib.standard_extensions" }}{{ else }}{{ range .default.cinder.osapi_volume_extension }}osapi_volume_extension = {{ . }}{{ end }}{{ end }}

# Full class name for the Manager for volume (string value)
# from .default.cinder.volume_manager
{{ if not .default.cinder.volume_manager }}#{{ end }}volume_manager = {{ .default.cinder.volume_manager | default "cinder.volume.manager.VolumeManager" }}

# Full class name for the Manager for volume backup (string value)
# from .default.cinder.backup_manager
{{ if not .default.cinder.backup_manager }}#{{ end }}backup_manager = {{ .default.cinder.backup_manager | default "cinder.backup.manager.BackupManager" }}

# Full class name for the Manager for scheduler (string value)
# from .default.cinder.scheduler_manager
{{ if not .default.cinder.scheduler_manager }}#{{ end }}scheduler_manager = {{ .default.cinder.scheduler_manager | default "cinder.scheduler.manager.SchedulerManager" }}

# Name of this node.  This can be an opaque identifier. It is not
# necessarily a host name, FQDN, or IP address. (string value)
# from .default.cinder.host
{{ if not .default.cinder.host }}#{{ end }}host = {{ .default.cinder.host | default "cinder-volume-worker" }}

# Availability zone of this node (string value)
# from .default.cinder.storage_availability_zone
{{ if not .default.cinder.storage_availability_zone }}#{{ end }}storage_availability_zone = {{ .default.cinder.storage_availability_zone | default "nova" }}

# Default availability zone for new volumes. If not set, the
# storage_availability_zone option value is used as the default for
# new volumes. (string value)
# from .default.cinder.default_availability_zone
{{ if not .default.cinder.default_availability_zone }}#{{ end }}default_availability_zone = {{ .default.cinder.default_availability_zone | default "<None>" }}

# If the requested Cinder availability zone is unavailable, fall back
# to the value of default_availability_zone, then
# storage_availability_zone, instead of failing. (boolean value)
# from .default.cinder.allow_availability_zone_fallback
{{ if not .default.cinder.allow_availability_zone_fallback }}#{{ end }}allow_availability_zone_fallback = {{ .default.cinder.allow_availability_zone_fallback | default "false" }}

# Default volume type to use (string value)
# from .default.cinder.default_volume_type
{{ if not .default.cinder.default_volume_type }}#{{ end }}default_volume_type = {{ .default.cinder.default_volume_type | default "<None>" }}

# Default group type to use (string value)
# from .default.cinder.default_group_type
{{ if not .default.cinder.default_group_type }}#{{ end }}default_group_type = {{ .default.cinder.default_group_type | default "<None>" }}

# Time period for which to generate volume usages. The options are
# hour, day, month, or year. (string value)
# from .default.cinder.volume_usage_audit_period
{{ if not .default.cinder.volume_usage_audit_period }}#{{ end }}volume_usage_audit_period = {{ .default.cinder.volume_usage_audit_period | default "month" }}

# Path to the rootwrap configuration file to use for running commands
# as root (string value)
# from .default.cinder.rootwrap_config
{{ if not .default.cinder.rootwrap_config }}#{{ end }}rootwrap_config = {{ .default.cinder.rootwrap_config | default "/etc/cinder/rootwrap.conf" }}

# Enable monkey patching (boolean value)
# from .default.cinder.monkey_patch
{{ if not .default.cinder.monkey_patch }}#{{ end }}monkey_patch = {{ .default.cinder.monkey_patch | default "false" }}

# List of modules/decorators to monkey patch (list value)
# from .default.cinder.monkey_patch_modules
{{ if not .default.cinder.monkey_patch_modules }}#{{ end }}monkey_patch_modules = {{ .default.cinder.monkey_patch_modules | default "" }}

# Maximum time since last check-in for a service to be considered up
# (integer value)
# from .default.cinder.service_down_time
{{ if not .default.cinder.service_down_time }}#{{ end }}service_down_time = {{ .default.cinder.service_down_time | default "60" }}

# The full class name of the volume API class to use (string value)
# from .default.cinder.volume_api_class
{{ if not .default.cinder.volume_api_class }}#{{ end }}volume_api_class = {{ .default.cinder.volume_api_class | default "cinder.volume.api.API" }}

# The full class name of the volume backup API class (string value)
# from .default.cinder.backup_api_class
{{ if not .default.cinder.backup_api_class }}#{{ end }}backup_api_class = {{ .default.cinder.backup_api_class | default "cinder.backup.api.API" }}

# The strategy to use for auth. Supports noauth or keystone. (string
# value)
# Allowed values: noauth, keystone
# from .default.cinder.auth_strategy
{{ if not .default.cinder.auth_strategy }}#{{ end }}auth_strategy = {{ .default.cinder.auth_strategy | default "keystone" }}

# A list of backend names to use. These backend names should be backed
# by a unique [CONFIG] group with its options (list value)
# from .default.cinder.enabled_backends
{{ if not .default.cinder.enabled_backends }}#{{ end }}enabled_backends = {{ .default.cinder.enabled_backends | default "<None>" }}

# Whether snapshots count against gigabyte quota (boolean value)
# from .default.cinder.no_snapshot_gb_quota
{{ if not .default.cinder.no_snapshot_gb_quota }}#{{ end }}no_snapshot_gb_quota = {{ .default.cinder.no_snapshot_gb_quota | default "false" }}

# The full class name of the volume transfer API class (string value)
# from .default.cinder.transfer_api_class
{{ if not .default.cinder.transfer_api_class }}#{{ end }}transfer_api_class = {{ .default.cinder.transfer_api_class | default "cinder.transfer.api.API" }}

# The full class name of the volume replication API class (string
# value)
# from .default.cinder.replication_api_class
{{ if not .default.cinder.replication_api_class }}#{{ end }}replication_api_class = {{ .default.cinder.replication_api_class | default "cinder.replication.api.API" }}

# The full class name of the consistencygroup API class (string value)
# from .default.cinder.consistencygroup_api_class
{{ if not .default.cinder.consistencygroup_api_class }}#{{ end }}consistencygroup_api_class = {{ .default.cinder.consistencygroup_api_class | default "cinder.consistencygroup.api.API" }}

# The full class name of the group API class (string value)
# from .default.cinder.group_api_class
{{ if not .default.cinder.group_api_class }}#{{ end }}group_api_class = {{ .default.cinder.group_api_class | default "cinder.group.api.API" }}

# OpenStack privileged account username. Used for requests to other
# services (such as Nova) that require an account with special rights.
# (string value)
# from .default.cinder.os_privileged_user_name
{{ if not .default.cinder.os_privileged_user_name }}#{{ end }}os_privileged_user_name = {{ .default.cinder.os_privileged_user_name | default "<None>" }}

# Password associated with the OpenStack privileged account. (string
# value)
# from .default.cinder.os_privileged_user_password
{{ if not .default.cinder.os_privileged_user_password }}#{{ end }}os_privileged_user_password = {{ .default.cinder.os_privileged_user_password | default "<None>" }}

# Tenant name associated with the OpenStack privileged account.
# (string value)
# from .default.cinder.os_privileged_user_tenant
{{ if not .default.cinder.os_privileged_user_tenant }}#{{ end }}os_privileged_user_tenant = {{ .default.cinder.os_privileged_user_tenant | default "<None>" }}

# Auth URL associated with the OpenStack privileged account. (string
# value)
# from .default.cinder.os_privileged_user_auth_url
{{ if not .default.cinder.os_privileged_user_auth_url }}#{{ end }}os_privileged_user_auth_url = {{ .default.cinder.os_privileged_user_auth_url | default "<None>" }}

# Multiplier used for weighing free capacity. Negative numbers mean to
# stack vs spread. (floating point value)
# from .default.cinder.capacity_weight_multiplier
{{ if not .default.cinder.capacity_weight_multiplier }}#{{ end }}capacity_weight_multiplier = {{ .default.cinder.capacity_weight_multiplier | default "1.0" }}

# Multiplier used for weighing allocated capacity. Positive numbers
# mean to stack vs spread. (floating point value)
# from .default.cinder.allocated_capacity_weight_multiplier
{{ if not .default.cinder.allocated_capacity_weight_multiplier }}#{{ end }}allocated_capacity_weight_multiplier = {{ .default.cinder.allocated_capacity_weight_multiplier | default "-1.0" }}

# Max size for body of a request (integer value)
# from .default.cinder.osapi_max_request_body_size
{{ if not .default.cinder.osapi_max_request_body_size }}#{{ end }}osapi_max_request_body_size = {{ .default.cinder.osapi_max_request_body_size | default "114688" }}

# The URL of the Swift endpoint (string value)
# from .default.cinder.backup_swift_url
{{ if not .default.cinder.backup_swift_url }}#{{ end }}backup_swift_url = {{ .default.cinder.backup_swift_url | default "<None>" }}

# The URL of the Keystone endpoint (string value)
# from .default.cinder.backup_swift_auth_url
{{ if not .default.cinder.backup_swift_auth_url }}#{{ end }}backup_swift_auth_url = {{ .default.cinder.backup_swift_auth_url | default "<None>" }}

# Info to match when looking for swift in the service catalog. Format
# is: separated values of the form:
# <service_type>:<service_name>:<endpoint_type> - Only used if
# backup_swift_url is unset (string value)
# from .default.cinder.swift_catalog_info
{{ if not .default.cinder.swift_catalog_info }}#{{ end }}swift_catalog_info = {{ .default.cinder.swift_catalog_info | default "object-store:swift:publicURL" }}

# Info to match when looking for keystone in the service catalog.
# Format is: separated values of the form:
# <service_type>:<service_name>:<endpoint_type> - Only used if
# backup_swift_auth_url is unset (string value)
# from .default.cinder.keystone_catalog_info
{{ if not .default.cinder.keystone_catalog_info }}#{{ end }}keystone_catalog_info = {{ .default.cinder.keystone_catalog_info | default "identity:Identity Service:publicURL" }}

# Swift authentication mechanism (string value)
# from .default.cinder.backup_swift_auth
{{ if not .default.cinder.backup_swift_auth }}#{{ end }}backup_swift_auth = {{ .default.cinder.backup_swift_auth | default "per_user" }}

# Swift authentication version. Specify "1" for auth 1.0, or "2" for
# auth 2.0 or "3" for auth 3.0 (string value)
# from .default.cinder.backup_swift_auth_version
{{ if not .default.cinder.backup_swift_auth_version }}#{{ end }}backup_swift_auth_version = {{ .default.cinder.backup_swift_auth_version | default "1" }}

# Swift tenant/account name. Required when connecting to an auth 2.0
# system (string value)
# from .default.cinder.backup_swift_tenant
{{ if not .default.cinder.backup_swift_tenant }}#{{ end }}backup_swift_tenant = {{ .default.cinder.backup_swift_tenant | default "<None>" }}

# Swift user domain name. Required when connecting to an auth 3.0
# system (string value)
# from .default.cinder.backup_swift_user_domain
{{ if not .default.cinder.backup_swift_user_domain }}#{{ end }}backup_swift_user_domain = {{ .default.cinder.backup_swift_user_domain | default "<None>" }}

# Swift project domain name. Required when connecting to an auth 3.0
# system (string value)
# from .default.cinder.backup_swift_project_domain
{{ if not .default.cinder.backup_swift_project_domain }}#{{ end }}backup_swift_project_domain = {{ .default.cinder.backup_swift_project_domain | default "<None>" }}

# Swift project/account name. Required when connecting to an auth 3.0
# system (string value)
# from .default.cinder.backup_swift_project
{{ if not .default.cinder.backup_swift_project }}#{{ end }}backup_swift_project = {{ .default.cinder.backup_swift_project | default "<None>" }}

# Swift user name (string value)
# from .default.cinder.backup_swift_user
{{ if not .default.cinder.backup_swift_user }}#{{ end }}backup_swift_user = {{ .default.cinder.backup_swift_user | default "<None>" }}

# Swift key for authentication (string value)
# from .default.cinder.backup_swift_key
{{ if not .default.cinder.backup_swift_key }}#{{ end }}backup_swift_key = {{ .default.cinder.backup_swift_key | default "<None>" }}

# The default Swift container to use (string value)
# from .default.cinder.backup_swift_container
{{ if not .default.cinder.backup_swift_container }}#{{ end }}backup_swift_container = {{ .default.cinder.backup_swift_container | default "volumebackups" }}

# The size in bytes of Swift backup objects (integer value)
# from .default.cinder.backup_swift_object_size
{{ if not .default.cinder.backup_swift_object_size }}#{{ end }}backup_swift_object_size = {{ .default.cinder.backup_swift_object_size | default "52428800" }}

# The size in bytes that changes are tracked for incremental backups.
# backup_swift_object_size has to be multiple of
# backup_swift_block_size. (integer value)
# from .default.cinder.backup_swift_block_size
{{ if not .default.cinder.backup_swift_block_size }}#{{ end }}backup_swift_block_size = {{ .default.cinder.backup_swift_block_size | default "32768" }}

# The number of retries to make for Swift operations (integer value)
# from .default.cinder.backup_swift_retry_attempts
{{ if not .default.cinder.backup_swift_retry_attempts }}#{{ end }}backup_swift_retry_attempts = {{ .default.cinder.backup_swift_retry_attempts | default "3" }}

# The backoff time in seconds between Swift retries (integer value)
# from .default.cinder.backup_swift_retry_backoff
{{ if not .default.cinder.backup_swift_retry_backoff }}#{{ end }}backup_swift_retry_backoff = {{ .default.cinder.backup_swift_retry_backoff | default "2" }}

# Enable or Disable the timer to send the periodic progress
# notifications to Ceilometer when backing up the volume to the Swift
# backend storage. The default value is True to enable the timer.
# (boolean value)
# from .default.cinder.backup_swift_enable_progress_timer
{{ if not .default.cinder.backup_swift_enable_progress_timer }}#{{ end }}backup_swift_enable_progress_timer = {{ .default.cinder.backup_swift_enable_progress_timer | default "true" }}

# Location of the CA certificate file to use for swift client
# requests. (string value)
# from .default.cinder.backup_swift_ca_cert_file
{{ if not .default.cinder.backup_swift_ca_cert_file }}#{{ end }}backup_swift_ca_cert_file = {{ .default.cinder.backup_swift_ca_cert_file | default "<None>" }}

# Bypass verification of server certificate when making SSL connection
# to Swift. (boolean value)
# from .default.cinder.backup_swift_auth_insecure
{{ if not .default.cinder.backup_swift_auth_insecure }}#{{ end }}backup_swift_auth_insecure = {{ .default.cinder.backup_swift_auth_insecure | default "false" }}

# Interval, in seconds, between nodes reporting state to datastore
# (integer value)
# from .default.cinder.report_interval
{{ if not .default.cinder.report_interval }}#{{ end }}report_interval = {{ .default.cinder.report_interval | default "10" }}

# Interval, in seconds, between running periodic tasks (integer value)
# from .default.cinder.periodic_interval
{{ if not .default.cinder.periodic_interval }}#{{ end }}periodic_interval = {{ .default.cinder.periodic_interval | default "60" }}

# Range, in seconds, to randomly delay when starting the periodic task
# scheduler to reduce stampeding. (Disable by setting to 0) (integer
# value)
# from .default.cinder.periodic_fuzzy_delay
{{ if not .default.cinder.periodic_fuzzy_delay }}#{{ end }}periodic_fuzzy_delay = {{ .default.cinder.periodic_fuzzy_delay | default "60" }}

# IP address on which OpenStack Volume API listens (string value)
# from .default.cinder.osapi_volume_listen
{{ if not .default.cinder.osapi_volume_listen }}#{{ end }}osapi_volume_listen = {{ .default.cinder.osapi_volume_listen | default "0.0.0.0" }}

# Port on which OpenStack Volume API listens (port value)
# Minimum value: 0
# Maximum value: 65535
# from .default.cinder.osapi_volume_listen_port
{{ if not .default.cinder.osapi_volume_listen_port }}#{{ end }}osapi_volume_listen_port = {{ .default.cinder.osapi_volume_listen_port | default "8776" }}

# Number of workers for OpenStack Volume API service. The default is
# equal to the number of CPUs available. (integer value)
# from .default.cinder.osapi_volume_workers
{{ if not .default.cinder.osapi_volume_workers }}#{{ end }}osapi_volume_workers = {{ .default.cinder.osapi_volume_workers | default "<None>" }}

# Wraps the socket in a SSL context if True is set. A certificate file
# and key file must be specified. (boolean value)
# from .default.cinder.osapi_volume_use_ssl
{{ if not .default.cinder.osapi_volume_use_ssl }}#{{ end }}osapi_volume_use_ssl = {{ .default.cinder.osapi_volume_use_ssl | default "false" }}

# The full class name of the compute API class to use (string value)
# from .default.cinder.compute_api_class
{{ if not .default.cinder.compute_api_class }}#{{ end }}compute_api_class = {{ .default.cinder.compute_api_class | default "cinder.compute.nova.API" }}

# ID of the project which will be used as the Cinder internal tenant.
# (string value)
# from .default.cinder.cinder_internal_tenant_project_id
{{ if not .default.cinder.cinder_internal_tenant_project_id }}#{{ end }}cinder_internal_tenant_project_id = {{ .default.cinder.cinder_internal_tenant_project_id | default "<None>" }}

# ID of the user to be used in volume operations as the Cinder
# internal tenant. (string value)
# from .default.cinder.cinder_internal_tenant_user_id
{{ if not .default.cinder.cinder_internal_tenant_user_id }}#{{ end }}cinder_internal_tenant_user_id = {{ .default.cinder.cinder_internal_tenant_user_id | default "<None>" }}

# The scheduler host manager class to use (string value)
# from .default.cinder.scheduler_host_manager
{{ if not .default.cinder.scheduler_host_manager }}#{{ end }}scheduler_host_manager = {{ .default.cinder.scheduler_host_manager | default "cinder.scheduler.host_manager.HostManager" }}

# Maximum number of attempts to schedule a volume (integer value)
# from .default.cinder.scheduler_max_attempts
{{ if not .default.cinder.scheduler_max_attempts }}#{{ end }}scheduler_max_attempts = {{ .default.cinder.scheduler_max_attempts | default "3" }}

# The maximum size in bytes of the files used to hold backups. If the
# volume being backed up exceeds this size, then it will be backed up
# into multiple files.backup_file_size must be a multiple of
# backup_sha_block_size_bytes. (integer value)
# from .default.cinder.backup_file_size
{{ if not .default.cinder.backup_file_size }}#{{ end }}backup_file_size = {{ .default.cinder.backup_file_size | default "1999994880" }}

# The size in bytes that changes are tracked for incremental backups.
# backup_file_size has to be multiple of backup_sha_block_size_bytes.
# (integer value)
# from .default.cinder.backup_sha_block_size_bytes
{{ if not .default.cinder.backup_sha_block_size_bytes }}#{{ end }}backup_sha_block_size_bytes = {{ .default.cinder.backup_sha_block_size_bytes | default "32768" }}

# Enable or Disable the timer to send the periodic progress
# notifications to Ceilometer when backing up the volume to the
# backend storage. The default value is True to enable the timer.
# (boolean value)
# from .default.cinder.backup_enable_progress_timer
{{ if not .default.cinder.backup_enable_progress_timer }}#{{ end }}backup_enable_progress_timer = {{ .default.cinder.backup_enable_progress_timer | default "true" }}

# Path specifying where to store backups. (string value)
# from .default.cinder.backup_posix_path
{{ if not .default.cinder.backup_posix_path }}#{{ end }}backup_posix_path = {{ .default.cinder.backup_posix_path | default "$state_path/backup" }}

# Custom directory to use for backups. (string value)
# from .default.cinder.backup_container
{{ if not .default.cinder.backup_container }}#{{ end }}backup_container = {{ .default.cinder.backup_container | default "<None>" }}

# Driver to use for database access (string value)
# from .default.cinder.db_driver
{{ if not .default.cinder.db_driver }}#{{ end }}db_driver = {{ .default.cinder.db_driver | default "cinder.db" }}

# The number of characters in the salt. (integer value)
# from .default.cinder.volume_transfer_salt_length
{{ if not .default.cinder.volume_transfer_salt_length }}#{{ end }}volume_transfer_salt_length = {{ .default.cinder.volume_transfer_salt_length | default "8" }}

# The number of characters in the autogenerated auth key. (integer
# value)
# from .default.cinder.volume_transfer_key_length
{{ if not .default.cinder.volume_transfer_key_length }}#{{ end }}volume_transfer_key_length = {{ .default.cinder.volume_transfer_key_length | default "16" }}

# Services to be added to the available pool on create (boolean value)
# from .default.cinder.enable_new_services
{{ if not .default.cinder.enable_new_services }}#{{ end }}enable_new_services = {{ .default.cinder.enable_new_services | default "true" }}

# Template string to be used to generate volume names (string value)
# from .default.cinder.volume_name_template
{{ if not .default.cinder.volume_name_template }}#{{ end }}volume_name_template = {{ .default.cinder.volume_name_template | default "volume-%s" }}

# Template string to be used to generate snapshot names (string value)
# from .default.cinder.snapshot_name_template
{{ if not .default.cinder.snapshot_name_template }}#{{ end }}snapshot_name_template = {{ .default.cinder.snapshot_name_template | default "snapshot-%s" }}

# Template string to be used to generate backup names (string value)
# from .default.cinder.backup_name_template
{{ if not .default.cinder.backup_name_template }}#{{ end }}backup_name_template = {{ .default.cinder.backup_name_template | default "backup-%s" }}

# Multiplier used for weighing volume number. Negative numbers mean to
# spread vs stack. (floating point value)
# from .default.cinder.volume_number_multiplier
{{ if not .default.cinder.volume_number_multiplier }}#{{ end }}volume_number_multiplier = {{ .default.cinder.volume_number_multiplier | default "-1.0" }}

# Number of times to attempt to run flakey shell commands (integer
# value)
# from .default.cinder.num_shell_tries
{{ if not .default.cinder.num_shell_tries }}#{{ end }}num_shell_tries = {{ .default.cinder.num_shell_tries | default "3" }}

# The percentage of backend capacity is reserved (integer value)
# Minimum value: 0
# Maximum value: 100
# from .default.cinder.reserved_percentage
{{ if not .default.cinder.reserved_percentage }}#{{ end }}reserved_percentage = {{ .default.cinder.reserved_percentage | default "0" }}

# Prefix for iSCSI volumes (string value)
# from .default.cinder.iscsi_target_prefix
{{ if not .default.cinder.iscsi_target_prefix }}#{{ end }}iscsi_target_prefix = {{ .default.cinder.iscsi_target_prefix | default "iqn.2010-10.org.openstack:" }}

# The IP address that the iSCSI daemon is listening on (string value)
# from .default.cinder.iscsi_ip_address
{{ if not .default.cinder.iscsi_ip_address }}#{{ end }}iscsi_ip_address = {{ .default.cinder.iscsi_ip_address | default "$my_ip" }}

# The list of secondary IP addresses of the iSCSI daemon (list value)
# from .default.cinder.iscsi_secondary_ip_addresses
{{ if not .default.cinder.iscsi_secondary_ip_addresses }}#{{ end }}iscsi_secondary_ip_addresses = {{ .default.cinder.iscsi_secondary_ip_addresses | default "" }}

# The port that the iSCSI daemon is listening on (port value)
# Minimum value: 0
# Maximum value: 65535
# from .default.cinder.iscsi_port
{{ if not .default.cinder.iscsi_port }}#{{ end }}iscsi_port = {{ .default.cinder.iscsi_port | default "3260" }}

# The maximum number of times to rescan targets to find volume
# (integer value)
# from .default.cinder.num_volume_device_scan_tries
{{ if not .default.cinder.num_volume_device_scan_tries }}#{{ end }}num_volume_device_scan_tries = {{ .default.cinder.num_volume_device_scan_tries | default "3" }}

# The backend name for a given driver implementation (string value)
# from .default.cinder.volume_backend_name
{{ if not .default.cinder.volume_backend_name }}#{{ end }}volume_backend_name = {{ .default.cinder.volume_backend_name | default "<None>" }}

# Do we attach/detach volumes in cinder using multipath for volume to
# image and image to volume transfers? (boolean value)
# from .default.cinder.use_multipath_for_image_xfer
{{ if not .default.cinder.use_multipath_for_image_xfer }}#{{ end }}use_multipath_for_image_xfer = {{ .default.cinder.use_multipath_for_image_xfer | default "false" }}

# If this is set to True, attachment of volumes for image transfer
# will be aborted when multipathd is not running. Otherwise, it will
# fallback to single path. (boolean value)
# from .default.cinder.enforce_multipath_for_image_xfer
{{ if not .default.cinder.enforce_multipath_for_image_xfer }}#{{ end }}enforce_multipath_for_image_xfer = {{ .default.cinder.enforce_multipath_for_image_xfer | default "false" }}

# Method used to wipe old volumes (string value)
# Allowed values: none, zero, shred
# from .default.cinder.volume_clear
{{ if not .default.cinder.volume_clear }}#{{ end }}volume_clear = {{ .default.cinder.volume_clear | default "zero" }}

# Size in MiB to wipe at start of old volumes. 1024 MiBat max. 0 =>
# all (integer value)
# Maximum value: 1024
# from .default.cinder.volume_clear_size
{{ if not .default.cinder.volume_clear_size }}#{{ end }}volume_clear_size = {{ .default.cinder.volume_clear_size | default "0" }}

# The flag to pass to ionice to alter the i/o priority of the process
# used to zero a volume after deletion, for example "-c3" for idle
# only priority. (string value)
# from .default.cinder.volume_clear_ionice
{{ if not .default.cinder.volume_clear_ionice }}#{{ end }}volume_clear_ionice = {{ .default.cinder.volume_clear_ionice | default "<None>" }}

# iSCSI target user-land tool to use. tgtadm is default, use lioadm
# for LIO iSCSI support, scstadmin for SCST target support, ietadm for
# iSCSI Enterprise Target, iscsictl for Chelsio iSCSI Target or fake
# for testing. (string value)
# Allowed values: tgtadm, lioadm, scstadmin, iscsictl, ietadm, fake
# from .default.cinder.iscsi_helper
{{ if not .default.cinder.iscsi_helper }}#{{ end }}iscsi_helper = {{ .default.cinder.iscsi_helper | default "tgtadm" }}

# Volume configuration file storage directory (string value)
# from .default.cinder.volumes_dir
{{ if not .default.cinder.volumes_dir }}#{{ end }}volumes_dir = {{ .default.cinder.volumes_dir | default "$state_path/volumes" }}

# IET configuration file (string value)
# from .default.cinder.iet_conf
{{ if not .default.cinder.iet_conf }}#{{ end }}iet_conf = {{ .default.cinder.iet_conf | default "/etc/iet/ietd.conf" }}

# Chiscsi (CXT) global defaults configuration file (string value)
# from .default.cinder.chiscsi_conf
{{ if not .default.cinder.chiscsi_conf }}#{{ end }}chiscsi_conf = {{ .default.cinder.chiscsi_conf | default "/etc/chelsio-iscsi/chiscsi.conf" }}

# Sets the behavior of the iSCSI target to either perform blockio or
# fileio optionally, auto can be set and Cinder will autodetect type
# of backing device (string value)
# Allowed values: blockio, fileio, auto
# from .default.cinder.iscsi_iotype
{{ if not .default.cinder.iscsi_iotype }}#{{ end }}iscsi_iotype = {{ .default.cinder.iscsi_iotype | default "fileio" }}

# The default block size used when copying/clearing volumes (string
# value)
# from .default.cinder.volume_dd_blocksize
{{ if not .default.cinder.volume_dd_blocksize }}#{{ end }}volume_dd_blocksize = {{ .default.cinder.volume_dd_blocksize | default "1M" }}

# The blkio cgroup name to be used to limit bandwidth of volume copy
# (string value)
# from .default.cinder.volume_copy_blkio_cgroup_name
{{ if not .default.cinder.volume_copy_blkio_cgroup_name }}#{{ end }}volume_copy_blkio_cgroup_name = {{ .default.cinder.volume_copy_blkio_cgroup_name | default "cinder-volume-copy" }}

# The upper limit of bandwidth of volume copy. 0 => unlimited (integer
# value)
# from .default.cinder.volume_copy_bps_limit
{{ if not .default.cinder.volume_copy_bps_limit }}#{{ end }}volume_copy_bps_limit = {{ .default.cinder.volume_copy_bps_limit | default "0" }}

# Sets the behavior of the iSCSI target to either perform write-
# back(on) or write-through(off). This parameter is valid if
# iscsi_helper is set to tgtadm. (string value)
# Allowed values: on, off
# from .default.cinder.iscsi_write_cache
{{ if not .default.cinder.iscsi_write_cache }}#{{ end }}iscsi_write_cache = {{ .default.cinder.iscsi_write_cache | default "on" }}

# Sets the target-specific flags for the iSCSI target. Only used for
# tgtadm to specify backing device flags using bsoflags option. The
# specified string is passed as is to the underlying tool. (string
# value)
# from .default.cinder.iscsi_target_flags
{{ if not .default.cinder.iscsi_target_flags }}#{{ end }}iscsi_target_flags = {{ .default.cinder.iscsi_target_flags | default "" }}

# Determines the iSCSI protocol for new iSCSI volumes, created with
# tgtadm or lioadm target helpers. In order to enable RDMA, this
# parameter should be set with the value "iser". The supported iSCSI
# protocol values are "iscsi" and "iser". (string value)
# Allowed values: iscsi, iser
# from .default.cinder.iscsi_protocol
{{ if not .default.cinder.iscsi_protocol }}#{{ end }}iscsi_protocol = {{ .default.cinder.iscsi_protocol | default "iscsi" }}

# The path to the client certificate key for verification, if the
# driver supports it. (string value)
# from .default.cinder.driver_client_cert_key
{{ if not .default.cinder.driver_client_cert_key }}#{{ end }}driver_client_cert_key = {{ .default.cinder.driver_client_cert_key | default "<None>" }}

# The path to the client certificate for verification, if the driver
# supports it. (string value)
# from .default.cinder.driver_client_cert
{{ if not .default.cinder.driver_client_cert }}#{{ end }}driver_client_cert = {{ .default.cinder.driver_client_cert | default "<None>" }}

# Tell driver to use SSL for connection to backend storage if the
# driver supports it. (boolean value)
# from .default.cinder.driver_use_ssl
{{ if not .default.cinder.driver_use_ssl }}#{{ end }}driver_use_ssl = {{ .default.cinder.driver_use_ssl | default "false" }}

# Float representation of the over subscription ratio when thin
# provisioning is involved. Default ratio is 20.0, meaning provisioned
# capacity can be 20 times of the total physical capacity. If the
# ratio is 10.5, it means provisioned capacity can be 10.5 times of
# the total physical capacity. A ratio of 1.0 means provisioned
# capacity cannot exceed the total physical capacity. The ratio has to
# be a minimum of 1.0. (floating point value)
# from .default.cinder.max_over_subscription_ratio
{{ if not .default.cinder.max_over_subscription_ratio }}#{{ end }}max_over_subscription_ratio = {{ .default.cinder.max_over_subscription_ratio | default "20.0" }}

# Certain ISCSI targets have predefined target names, SCST target
# driver uses this name. (string value)
# from .default.cinder.scst_target_iqn_name
{{ if not .default.cinder.scst_target_iqn_name }}#{{ end }}scst_target_iqn_name = {{ .default.cinder.scst_target_iqn_name | default "<None>" }}

# SCST target implementation can choose from multiple SCST target
# drivers. (string value)
# from .default.cinder.scst_target_driver
{{ if not .default.cinder.scst_target_driver }}#{{ end }}scst_target_driver = {{ .default.cinder.scst_target_driver | default "iscsi" }}

# Option to enable/disable CHAP authentication for targets. (boolean
# value)
# Deprecated group/name - [DEFAULT]/eqlx_use_chap
# from .default.cinder.use_chap_auth
{{ if not .default.cinder.use_chap_auth }}#{{ end }}use_chap_auth = {{ .default.cinder.use_chap_auth | default "false" }}

# CHAP user name. (string value)
# Deprecated group/name - [DEFAULT]/eqlx_chap_login
# from .default.cinder.chap_username
{{ if not .default.cinder.chap_username }}#{{ end }}chap_username = {{ .default.cinder.chap_username | default "" }}

# Password for specified CHAP account name. (string value)
# Deprecated group/name - [DEFAULT]/eqlx_chap_password
# from .default.cinder.chap_password
{{ if not .default.cinder.chap_password }}#{{ end }}chap_password = {{ .default.cinder.chap_password | default "" }}

# Namespace for driver private data values to be saved in. (string
# value)
# from .default.cinder.driver_data_namespace
{{ if not .default.cinder.driver_data_namespace }}#{{ end }}driver_data_namespace = {{ .default.cinder.driver_data_namespace | default "<None>" }}

# String representation for an equation that will be used to filter
# hosts. Only used when the driver filter is set to be used by the
# Cinder scheduler. (string value)
# from .default.cinder.filter_function
{{ if not .default.cinder.filter_function }}#{{ end }}filter_function = {{ .default.cinder.filter_function | default "<None>" }}

# String representation for an equation that will be used to determine
# the goodness of a host. Only used when using the goodness weigher is
# set to be used by the Cinder scheduler. (string value)
# from .default.cinder.goodness_function
{{ if not .default.cinder.goodness_function }}#{{ end }}goodness_function = {{ .default.cinder.goodness_function | default "<None>" }}

# If set to True the http client will validate the SSL certificate of
# the backend endpoint. (boolean value)
# from .default.cinder.driver_ssl_cert_verify
{{ if not .default.cinder.driver_ssl_cert_verify }}#{{ end }}driver_ssl_cert_verify = {{ .default.cinder.driver_ssl_cert_verify | default "false" }}

# Can be used to specify a non default path to a CA_BUNDLE file or
# directory with certificates of trusted CAs, which will be used to
# validate the backend (string value)
# from .default.cinder.driver_ssl_cert_path
{{ if not .default.cinder.driver_ssl_cert_path }}#{{ end }}driver_ssl_cert_path = {{ .default.cinder.driver_ssl_cert_path | default "<None>" }}

# List of options that control which trace info is written to the
# DEBUG log level to assist developers. Valid values are method and
# api. (list value)
# from .default.cinder.trace_flags
{{ if not .default.cinder.trace_flags }}#{{ end }}trace_flags = {{ .default.cinder.trace_flags | default "<None>" }}

# Multi opt of dictionaries to represent a replication target device.
# This option may be specified multiple times in a single config
# section to specify multiple replication target devices.  Each entry
# takes the standard dict config form: replication_device =
# target_device_id:<required>,key1:value1,key2:value2... (dict value)
# from .default.cinder.replication_device (multiopt)
{{ if not .default.cinder.replication_device }}#replication_device = {{ .default.cinder.replication_device | default "<None>" }}{{ else }}{{ range .default.cinder.replication_device }}replication_device = {{ . }}{{ end }}{{ end }}

# If set to True, upload-to-image in raw format will create a cloned
# volume and register its location to the image service, instead of
# uploading the volume content. The cinder backend and locations
# support must be enabled in the image service, and glance_api_version
# must be set to 2. (boolean value)
# from .default.cinder.image_upload_use_cinder_backend
{{ if not .default.cinder.image_upload_use_cinder_backend }}#{{ end }}image_upload_use_cinder_backend = {{ .default.cinder.image_upload_use_cinder_backend | default "false" }}

# If set to True, the image volume created by upload-to-image will be
# placed in the internal tenant. Otherwise, the image volume is
# created in the current context's tenant. (boolean value)
# from .default.cinder.image_upload_use_internal_tenant
{{ if not .default.cinder.image_upload_use_internal_tenant }}#{{ end }}image_upload_use_internal_tenant = {{ .default.cinder.image_upload_use_internal_tenant | default "false" }}

# Enable the image volume cache for this backend. (boolean value)
# from .default.cinder.image_volume_cache_enabled
{{ if not .default.cinder.image_volume_cache_enabled }}#{{ end }}image_volume_cache_enabled = {{ .default.cinder.image_volume_cache_enabled | default "false" }}

# Max size of the image volume cache for this backend in GB. 0 =>
# unlimited. (integer value)
# from .default.cinder.image_volume_cache_max_size_gb
{{ if not .default.cinder.image_volume_cache_max_size_gb }}#{{ end }}image_volume_cache_max_size_gb = {{ .default.cinder.image_volume_cache_max_size_gb | default "0" }}

# Max number of entries allowed in the image volume cache. 0 =>
# unlimited. (integer value)
# from .default.cinder.image_volume_cache_max_count
{{ if not .default.cinder.image_volume_cache_max_count }}#{{ end }}image_volume_cache_max_count = {{ .default.cinder.image_volume_cache_max_count | default "0" }}

# Report to clients of Cinder that the backend supports discard (aka.
# trim/unmap). This will not actually change the behavior of the
# backend or the client directly, it will only notify that it can be
# used. (boolean value)
# from .default.cinder.report_discard_supported
{{ if not .default.cinder.report_discard_supported }}#{{ end }}report_discard_supported = {{ .default.cinder.report_discard_supported | default "false" }}

# Protocol for transferring data between host and storage back-end.
# (string value)
# Allowed values: iscsi, fc
# from .default.cinder.storage_protocol
{{ if not .default.cinder.storage_protocol }}#{{ end }}storage_protocol = {{ .default.cinder.storage_protocol | default "iscsi" }}

# If this is set to True, the backup_use_temp_snapshot path will be
# used during the backup. Otherwise, it will use
# backup_use_temp_volume path. (boolean value)
# from .default.cinder.backup_use_temp_snapshot
{{ if not .default.cinder.backup_use_temp_snapshot }}#{{ end }}backup_use_temp_snapshot = {{ .default.cinder.backup_use_temp_snapshot | default "false" }}

# Set this to True when you want to allow an unsupported driver to
# start.  Drivers that haven't maintained a working CI system and
# testing are marked as unsupported until CI is working again.  This
# also marks a driver as deprecated and may be removed in the next
# release. (boolean value)
# from .default.cinder.enable_unsupported_driver
{{ if not .default.cinder.enable_unsupported_driver }}#{{ end }}enable_unsupported_driver = {{ .default.cinder.enable_unsupported_driver | default "false" }}

# The maximum number of times to rescan iSER targetto find volume
# (integer value)
# from .default.cinder.num_iser_scan_tries
{{ if not .default.cinder.num_iser_scan_tries }}#{{ end }}num_iser_scan_tries = {{ .default.cinder.num_iser_scan_tries | default "3" }}

# Prefix for iSER volumes (string value)
# from .default.cinder.iser_target_prefix
{{ if not .default.cinder.iser_target_prefix }}#{{ end }}iser_target_prefix = {{ .default.cinder.iser_target_prefix | default "iqn.2010-10.org.openstack:" }}

# The IP address that the iSER daemon is listening on (string value)
# from .default.cinder.iser_ip_address
{{ if not .default.cinder.iser_ip_address }}#{{ end }}iser_ip_address = {{ .default.cinder.iser_ip_address | default "$my_ip" }}

# The port that the iSER daemon is listening on (port value)
# Minimum value: 0
# Maximum value: 65535
# from .default.cinder.iser_port
{{ if not .default.cinder.iser_port }}#{{ end }}iser_port = {{ .default.cinder.iser_port | default "3260" }}

# The name of the iSER target user-land tool to use (string value)
# from .default.cinder.iser_helper
{{ if not .default.cinder.iser_helper }}#{{ end }}iser_helper = {{ .default.cinder.iser_helper | default "tgtadm" }}

# Public url to use for versions endpoint. The default is None, which
# will use the request's host_url attribute to populate the URL base.
# If Cinder is operating behind a proxy, you will want to change this
# to represent the proxy's URL. (string value)
# from .default.cinder.public_endpoint
{{ if not .default.cinder.public_endpoint }}#{{ end }}public_endpoint = {{ .default.cinder.public_endpoint | default "<None>" }}

# A list of url schemes that can be downloaded directly via the
# direct_url.  Currently supported schemes: [file]. (list value)
# from .default.cinder.allowed_direct_url_schemes
{{ if not .default.cinder.allowed_direct_url_schemes }}#{{ end }}allowed_direct_url_schemes = {{ .default.cinder.allowed_direct_url_schemes | default "" }}

# Info to match when looking for glance in the service catalog. Format
# is: separated values of the form:
# <service_type>:<service_name>:<endpoint_type> - Only used if
# glance_api_servers are not provided. (string value)
# from .default.cinder.glance_catalog_info
{{ if not .default.cinder.glance_catalog_info }}#{{ end }}glance_catalog_info = {{ .default.cinder.glance_catalog_info | default "image:glance:publicURL" }}

# Default core properties of image (list value)
# from .default.cinder.glance_core_properties
{{ if not .default.cinder.glance_core_properties }}#{{ end }}glance_core_properties = {{ .default.cinder.glance_core_properties | default "checksum,container_format,disk_format,image_name,image_id,min_disk,min_ram,name,size" }}

# The GCS bucket to use. (string value)
# from .default.cinder.backup_gcs_bucket
{{ if not .default.cinder.backup_gcs_bucket }}#{{ end }}backup_gcs_bucket = {{ .default.cinder.backup_gcs_bucket | default "<None>" }}

# The size in bytes of GCS backup objects. (integer value)
# from .default.cinder.backup_gcs_object_size
{{ if not .default.cinder.backup_gcs_object_size }}#{{ end }}backup_gcs_object_size = {{ .default.cinder.backup_gcs_object_size | default "52428800" }}

# The size in bytes that changes are tracked for incremental backups.
# backup_gcs_object_size has to be multiple of backup_gcs_block_size.
# (integer value)
# from .default.cinder.backup_gcs_block_size
{{ if not .default.cinder.backup_gcs_block_size }}#{{ end }}backup_gcs_block_size = {{ .default.cinder.backup_gcs_block_size | default "32768" }}

# GCS object will be downloaded in chunks of bytes. (integer value)
# from .default.cinder.backup_gcs_reader_chunk_size
{{ if not .default.cinder.backup_gcs_reader_chunk_size }}#{{ end }}backup_gcs_reader_chunk_size = {{ .default.cinder.backup_gcs_reader_chunk_size | default "2097152" }}

# GCS object will be uploaded in chunks of bytes. Pass in a value of
# -1 if the file is to be uploaded as a single chunk. (integer value)
# from .default.cinder.backup_gcs_writer_chunk_size
{{ if not .default.cinder.backup_gcs_writer_chunk_size }}#{{ end }}backup_gcs_writer_chunk_size = {{ .default.cinder.backup_gcs_writer_chunk_size | default "2097152" }}

# Number of times to retry. (integer value)
# from .default.cinder.backup_gcs_num_retries
{{ if not .default.cinder.backup_gcs_num_retries }}#{{ end }}backup_gcs_num_retries = {{ .default.cinder.backup_gcs_num_retries | default "3" }}

# List of GCS error codes. (list value)
# from .default.cinder.backup_gcs_retry_error_codes
{{ if not .default.cinder.backup_gcs_retry_error_codes }}#{{ end }}backup_gcs_retry_error_codes = {{ .default.cinder.backup_gcs_retry_error_codes | default "429" }}

# Location of GCS bucket. (string value)
# from .default.cinder.backup_gcs_bucket_location
{{ if not .default.cinder.backup_gcs_bucket_location }}#{{ end }}backup_gcs_bucket_location = {{ .default.cinder.backup_gcs_bucket_location | default "US" }}

# Storage class of GCS bucket. (string value)
# from .default.cinder.backup_gcs_storage_class
{{ if not .default.cinder.backup_gcs_storage_class }}#{{ end }}backup_gcs_storage_class = {{ .default.cinder.backup_gcs_storage_class | default "NEARLINE" }}

# Absolute path of GCS service account credential file. (string value)
# from .default.cinder.backup_gcs_credential_file
{{ if not .default.cinder.backup_gcs_credential_file }}#{{ end }}backup_gcs_credential_file = {{ .default.cinder.backup_gcs_credential_file | default "<None>" }}

# Owner project id for GCS bucket. (string value)
# from .default.cinder.backup_gcs_project_id
{{ if not .default.cinder.backup_gcs_project_id }}#{{ end }}backup_gcs_project_id = {{ .default.cinder.backup_gcs_project_id | default "<None>" }}

# Http user-agent string for gcs api. (string value)
# from .default.cinder.backup_gcs_user_agent
{{ if not .default.cinder.backup_gcs_user_agent }}#{{ end }}backup_gcs_user_agent = {{ .default.cinder.backup_gcs_user_agent | default "gcscinder" }}

# Enable or Disable the timer to send the periodic progress
# notifications to Ceilometer when backing up the volume to the GCS
# backend storage. The default value is True to enable the timer.
# (boolean value)
# from .default.cinder.backup_gcs_enable_progress_timer
{{ if not .default.cinder.backup_gcs_enable_progress_timer }}#{{ end }}backup_gcs_enable_progress_timer = {{ .default.cinder.backup_gcs_enable_progress_timer | default "true" }}

# URL for http proxy access. (uri value)
# from .default.cinder.backup_gcs_proxy_url
{{ if not .default.cinder.backup_gcs_proxy_url }}#{{ end }}backup_gcs_proxy_url = {{ .default.cinder.backup_gcs_proxy_url | default "<None>" }}

# Treat X-Forwarded-For as the canonical remote address. Only enable
# this if you have a sanitizing proxy. (boolean value)
# from .default.cinder.use_forwarded_for
{{ if not .default.cinder.use_forwarded_for }}#{{ end }}use_forwarded_for = {{ .default.cinder.use_forwarded_for | default "false" }}

# Backup services use same backend. (boolean value)
# from .default.cinder.backup_use_same_host
{{ if not .default.cinder.backup_use_same_host }}#{{ end }}backup_use_same_host = {{ .default.cinder.backup_use_same_host | default "false" }}

# Driver to use for backups. (string value)
# from .default.cinder.backup_driver
{{ if not .default.cinder.backup_driver }}#{{ end }}backup_driver = {{ .default.cinder.backup_driver | default "cinder.backup.drivers.swift" }}

# Offload pending backup delete during backup service startup. If
# false, the backup service will remain down until all pending backups
# are deleted. (boolean value)
# from .default.cinder.backup_service_inithost_offload
{{ if not .default.cinder.backup_service_inithost_offload }}#{{ end }}backup_service_inithost_offload = {{ .default.cinder.backup_service_inithost_offload | default "true" }}

# Number of volumes allowed per project (integer value)
# from .default.cinder.quota_volumes
{{ if not .default.cinder.quota_volumes }}#{{ end }}quota_volumes = {{ .default.cinder.quota_volumes | default "10" }}

# Number of volume snapshots allowed per project (integer value)
# from .default.cinder.quota_snapshots
{{ if not .default.cinder.quota_snapshots }}#{{ end }}quota_snapshots = {{ .default.cinder.quota_snapshots | default "10" }}

# Number of consistencygroups allowed per project (integer value)
# from .default.cinder.quota_consistencygroups
{{ if not .default.cinder.quota_consistencygroups }}#{{ end }}quota_consistencygroups = {{ .default.cinder.quota_consistencygroups | default "10" }}

# Number of groups allowed per project (integer value)
# from .default.cinder.quota_groups
{{ if not .default.cinder.quota_groups }}#{{ end }}quota_groups = {{ .default.cinder.quota_groups | default "10" }}

# Total amount of storage, in gigabytes, allowed for volumes and
# snapshots per project (integer value)
# from .default.cinder.quota_gigabytes
{{ if not .default.cinder.quota_gigabytes }}#{{ end }}quota_gigabytes = {{ .default.cinder.quota_gigabytes | default "1000" }}

# Number of volume backups allowed per project (integer value)
# from .default.cinder.quota_backups
{{ if not .default.cinder.quota_backups }}#{{ end }}quota_backups = {{ .default.cinder.quota_backups | default "10" }}

# Total amount of storage, in gigabytes, allowed for backups per
# project (integer value)
# from .default.cinder.quota_backup_gigabytes
{{ if not .default.cinder.quota_backup_gigabytes }}#{{ end }}quota_backup_gigabytes = {{ .default.cinder.quota_backup_gigabytes | default "1000" }}

# Number of seconds until a reservation expires (integer value)
# from .default.cinder.reservation_expire
{{ if not .default.cinder.reservation_expire }}#{{ end }}reservation_expire = {{ .default.cinder.reservation_expire | default "86400" }}

# Count of reservations until usage is refreshed (integer value)
# from .default.cinder.until_refresh
{{ if not .default.cinder.until_refresh }}#{{ end }}until_refresh = {{ .default.cinder.until_refresh | default "0" }}

# Number of seconds between subsequent usage refreshes (integer value)
# from .default.cinder.max_age
{{ if not .default.cinder.max_age }}#{{ end }}max_age = {{ .default.cinder.max_age | default "0" }}

# Default driver to use for quota checks (string value)
# from .default.cinder.quota_driver
{{ if not .default.cinder.quota_driver }}#{{ end }}quota_driver = {{ .default.cinder.quota_driver | default "cinder.quota.DbQuotaDriver" }}

# Enables or disables use of default quota class with default quota.
# (boolean value)
# from .default.cinder.use_default_quota_class
{{ if not .default.cinder.use_default_quota_class }}#{{ end }}use_default_quota_class = {{ .default.cinder.use_default_quota_class | default "true" }}

# Max size allowed per volume, in gigabytes (integer value)
# from .default.cinder.per_volume_size_limit
{{ if not .default.cinder.per_volume_size_limit }}#{{ end }}per_volume_size_limit = {{ .default.cinder.per_volume_size_limit | default "-1" }}

# Which filter class names to use for filtering hosts when not
# specified in the request. (list value)
# from .default.cinder.scheduler_default_filters
{{ if not .default.cinder.scheduler_default_filters }}#{{ end }}scheduler_default_filters = {{ .default.cinder.scheduler_default_filters | default "AvailabilityZoneFilter,CapacityFilter,CapabilitiesFilter" }}

# Which weigher class names to use for weighing hosts. (list value)
# from .default.cinder.scheduler_default_weighers
{{ if not .default.cinder.scheduler_default_weighers }}#{{ end }}scheduler_default_weighers = {{ .default.cinder.scheduler_default_weighers | default "CapacityWeigher" }}

# Which handler to use for selecting the host/pool after weighing
# (string value)
# from .default.cinder.scheduler_weight_handler
{{ if not .default.cinder.scheduler_weight_handler }}#{{ end }}scheduler_weight_handler = {{ .default.cinder.scheduler_weight_handler | default "cinder.scheduler.weights.OrderedHostWeightHandler" }}

# Default scheduler driver to use (string value)
# from .default.cinder.scheduler_driver
{{ if not .default.cinder.scheduler_driver }}#{{ end }}scheduler_driver = {{ .default.cinder.scheduler_driver | default "cinder.scheduler.filter_scheduler.FilterScheduler" }}

# Base dir containing mount point for NFS share. (string value)
# from .default.cinder.backup_mount_point_base
{{ if not .default.cinder.backup_mount_point_base }}#{{ end }}backup_mount_point_base = {{ .default.cinder.backup_mount_point_base | default "$state_path/backup_mount" }}

# NFS share in hostname:path, ipv4addr:path, or "[ipv6addr]:path"
# format. (string value)
# from .default.cinder.backup_share
{{ if not .default.cinder.backup_share }}#{{ end }}backup_share = {{ .default.cinder.backup_share | default "<None>" }}

# Mount options passed to the NFS client. See NFS man page for
# details. (string value)
# from .default.cinder.backup_mount_options
{{ if not .default.cinder.backup_mount_options }}#{{ end }}backup_mount_options = {{ .default.cinder.backup_mount_options | default "<None>" }}

# Absolute path to scheduler configuration JSON file. (string value)
# from .default.cinder.scheduler_json_config_location
{{ if not .default.cinder.scheduler_json_config_location }}#{{ end }}scheduler_json_config_location = {{ .default.cinder.scheduler_json_config_location | default "" }}

# message minimum life in seconds. (integer value)
# from .default.cinder.message_ttl
{{ if not .default.cinder.message_ttl }}#{{ end }}message_ttl = {{ .default.cinder.message_ttl | default "2592000" }}

# Directory used for temporary storage during image conversion (string
# value)
# from .default.cinder.image_conversion_dir
{{ if not .default.cinder.image_conversion_dir }}#{{ end }}image_conversion_dir = {{ .default.cinder.image_conversion_dir | default "$state_path/conversion" }}

# Match this value when searching for nova in the service catalog.
# Format is: separated values of the form:
# <service_type>:<service_name>:<endpoint_type> (string value)
# from .default.cinder.nova_catalog_info
{{ if not .default.cinder.nova_catalog_info }}#{{ end }}nova_catalog_info = {{ .default.cinder.nova_catalog_info | default "compute:Compute Service:publicURL" }}

# Same as nova_catalog_info, but for admin endpoint. (string value)
# from .default.cinder.nova_catalog_admin_info
{{ if not .default.cinder.nova_catalog_admin_info }}#{{ end }}nova_catalog_admin_info = {{ .default.cinder.nova_catalog_admin_info | default "compute:Compute Service:adminURL" }}

# Override service catalog lookup with template for nova endpoint e.g.
# http://localhost:8774/v2/%(project_id)s (string value)
# from .default.cinder.nova_endpoint_template
{{ if not .default.cinder.nova_endpoint_template }}#{{ end }}nova_endpoint_template = {{ .default.cinder.nova_endpoint_template | default "<None>" }}

# Same as nova_endpoint_template, but for admin endpoint. (string
# value)
# from .default.cinder.nova_endpoint_admin_template
{{ if not .default.cinder.nova_endpoint_admin_template }}#{{ end }}nova_endpoint_admin_template = {{ .default.cinder.nova_endpoint_admin_template | default "<None>" }}

# Region name of this node (string value)
# from .default.cinder.os_region_name
{{ if not .default.cinder.os_region_name }}#{{ end }}os_region_name = {{ .default.cinder.os_region_name | default "<None>" }}

# Location of ca certificates file to use for nova client requests.
# (string value)
# from .default.cinder.nova_ca_certificates_file
{{ if not .default.cinder.nova_ca_certificates_file }}#{{ end }}nova_ca_certificates_file = {{ .default.cinder.nova_ca_certificates_file | default "<None>" }}

# Allow to perform insecure SSL requests to nova (boolean value)
# from .default.cinder.nova_api_insecure
{{ if not .default.cinder.nova_api_insecure }}#{{ end }}nova_api_insecure = {{ .default.cinder.nova_api_insecure | default "false" }}

# Driver to use for volume creation (string value)
# from .default.cinder.volume_driver
{{ if not .default.cinder.volume_driver }}#{{ end }}volume_driver = {{ .default.cinder.volume_driver | default "cinder.volume.drivers.lvm.LVMVolumeDriver" }}

# Timeout for creating the volume to migrate to when performing volume
# migration (seconds) (integer value)
# from .default.cinder.migration_create_volume_timeout_secs
{{ if not .default.cinder.migration_create_volume_timeout_secs }}#{{ end }}migration_create_volume_timeout_secs = {{ .default.cinder.migration_create_volume_timeout_secs | default "300" }}

# Offload pending volume delete during volume service startup (boolean
# value)
# from .default.cinder.volume_service_inithost_offload
{{ if not .default.cinder.volume_service_inithost_offload }}#{{ end }}volume_service_inithost_offload = {{ .default.cinder.volume_service_inithost_offload | default "false" }}

# FC Zoning mode configured (string value)
# from .default.cinder.zoning_mode
{{ if not .default.cinder.zoning_mode }}#{{ end }}zoning_mode = {{ .default.cinder.zoning_mode | default "<None>" }}

# User defined capabilities, a JSON formatted string specifying
# key/value pairs. The key/value pairs can be used by the
# CapabilitiesFilter to select between backends when requests specify
# volume types. For example, specifying a service level or the
# geographical location of a backend, then creating a volume type to
# allow the user to select by these different properties. (string
# value)
# from .default.cinder.extra_capabilities
{{ if not .default.cinder.extra_capabilities }}#{{ end }}extra_capabilities = {{ .default.cinder.extra_capabilities | default "{}" }}

# Suppress requests library SSL certificate warnings. (boolean value)
# from .default.cinder.suppress_requests_ssl_warnings
{{ if not .default.cinder.suppress_requests_ssl_warnings }}#{{ end }}suppress_requests_ssl_warnings = {{ .default.cinder.suppress_requests_ssl_warnings | default "false" }}

# Enables the Force option on upload_to_image. This enables running
# upload_volume on in-use volumes for backends that support it.
# (boolean value)
# from .default.cinder.enable_force_upload
{{ if not .default.cinder.enable_force_upload }}#{{ end }}enable_force_upload = {{ .default.cinder.enable_force_upload | default "false" }}

# Create volume from snapshot at the host where snapshot resides
# (boolean value)
# from .default.cinder.snapshot_same_host
{{ if not .default.cinder.snapshot_same_host }}#{{ end }}snapshot_same_host = {{ .default.cinder.snapshot_same_host | default "true" }}

# Ensure that the new volumes are the same AZ as snapshot or source
# volume (boolean value)
# from .default.cinder.cloned_volume_same_az
{{ if not .default.cinder.cloned_volume_same_az }}#{{ end }}cloned_volume_same_az = {{ .default.cinder.cloned_volume_same_az | default "true" }}

# Cache volume availability zones in memory for the provided duration
# in seconds (integer value)
# from .default.cinder.az_cache_duration
{{ if not .default.cinder.az_cache_duration }}#{{ end }}az_cache_duration = {{ .default.cinder.az_cache_duration | default "3600" }}

#
# From oslo.config
#

# Path to a config file to use. Multiple config files can be
# specified, with values in later files taking precedence. Defaults to
# %(default)s. (unknown value)
# from .default.oslo.config.config_file
{{ if not .default.oslo.config.config_file }}#{{ end }}config_file = {{ .default.oslo.config.config_file | default "~/.project/project.conf,~/project.conf,/etc/project/project.conf,/etc/project.conf" }}

# Path to a config directory to pull *.conf files from. This file set
# is sorted, so as to provide a predictable parse order if individual
# options are over-ridden. The set is parsed after the file(s)
# specified via previous --config-file, arguments hence over-ridden
# options in the directory take precedence. (list value)
# from .default.oslo.config.config_dir
{{ if not .default.oslo.config.config_dir }}#{{ end }}config_dir = {{ .default.oslo.config.config_dir | default "<None>" }}

#
# From oslo.log
#

# If set to true, the logging level will be set to DEBUG instead of
# the default INFO level. (boolean value)
# Note: This option can be changed without restarting.
# from .default.oslo.log.debug
{{ if not .default.oslo.log.debug }}#{{ end }}debug = {{ .default.oslo.log.debug | default "false" }}

# DEPRECATED: If set to false, the logging level will be set to
# WARNING instead of the default INFO level. (boolean value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# from .default.oslo.log.verbose
{{ if not .default.oslo.log.verbose }}#{{ end }}verbose = {{ .default.oslo.log.verbose | default "true" }}

# The name of a logging configuration file. This file is appended to
# any existing logging configuration files. For details about logging
# configuration files, see the Python logging module documentation.
# Note that when logging configuration files are used then all logging
# configuration is set in the configuration file and other logging
# configuration options are ignored (for example,
# logging_context_format_string). (string value)
# Note: This option can be changed without restarting.
# Deprecated group/name - [DEFAULT]/log_config
# from .default.oslo.log.log_config_append
{{ if not .default.oslo.log.log_config_append }}#{{ end }}log_config_append = {{ .default.oslo.log.log_config_append | default "<None>" }}

# Defines the format string for %%(asctime)s in log records. Default:
# %(default)s . This option is ignored if log_config_append is set.
# (string value)
# from .default.oslo.log.log_date_format
{{ if not .default.oslo.log.log_date_format }}#{{ end }}log_date_format = {{ .default.oslo.log.log_date_format | default "%Y-%m-%d %H:%M:%S" }}

# (Optional) Name of log file to send logging output to. If no default
# is set, logging will go to stderr as defined by use_stderr. This
# option is ignored if log_config_append is set. (string value)
# Deprecated group/name - [DEFAULT]/logfile
# from .default.oslo.log.log_file
{{ if not .default.oslo.log.log_file }}#{{ end }}log_file = {{ .default.oslo.log.log_file | default "<None>" }}

# (Optional) The base directory used for relative log_file  paths.
# This option is ignored if log_config_append is set. (string value)
# Deprecated group/name - [DEFAULT]/logdir
# from .default.oslo.log.log_dir
{{ if not .default.oslo.log.log_dir }}#{{ end }}log_dir = {{ .default.oslo.log.log_dir | default "<None>" }}

# Uses logging handler designed to watch file system. When log file is
# moved or removed this handler will open a new log file with
# specified path instantaneously. It makes sense only if log_file
# option is specified and Linux platform is used. This option is
# ignored if log_config_append is set. (boolean value)
# from .default.oslo.log.watch_log_file
{{ if not .default.oslo.log.watch_log_file }}#{{ end }}watch_log_file = {{ .default.oslo.log.watch_log_file | default "false" }}

# Use syslog for logging. Existing syslog format is DEPRECATED and
# will be changed later to honor RFC5424. This option is ignored if
# log_config_append is set. (boolean value)
# from .default.oslo.log.use_syslog
{{ if not .default.oslo.log.use_syslog }}#{{ end }}use_syslog = {{ .default.oslo.log.use_syslog | default "false" }}

# Syslog facility to receive log lines. This option is ignored if
# log_config_append is set. (string value)
# from .default.oslo.log.syslog_log_facility
{{ if not .default.oslo.log.syslog_log_facility }}#{{ end }}syslog_log_facility = {{ .default.oslo.log.syslog_log_facility | default "LOG_USER" }}

# Log output to standard error. This option is ignored if
# log_config_append is set. (boolean value)
# from .default.oslo.log.use_stderr
{{ if not .default.oslo.log.use_stderr }}#{{ end }}use_stderr = {{ .default.oslo.log.use_stderr | default "true" }}

# Format string to use for log messages with context. (string value)
# from .default.oslo.log.logging_context_format_string
{{ if not .default.oslo.log.logging_context_format_string }}#{{ end }}logging_context_format_string = {{ .default.oslo.log.logging_context_format_string | default "%(asctime)s.%(msecs)03d %(process)d %(levelname)s %(name)s [%(request_id)s %(user_identity)s] %(instance)s%(message)s" }}

# Format string to use for log messages when context is undefined.
# (string value)
# from .default.oslo.log.logging_default_format_string
{{ if not .default.oslo.log.logging_default_format_string }}#{{ end }}logging_default_format_string = {{ .default.oslo.log.logging_default_format_string | default "%(asctime)s.%(msecs)03d %(process)d %(levelname)s %(name)s [-] %(instance)s%(message)s" }}

# Additional data to append to log message when logging level for the
# message is DEBUG. (string value)
# from .default.oslo.log.logging_debug_format_suffix
{{ if not .default.oslo.log.logging_debug_format_suffix }}#{{ end }}logging_debug_format_suffix = {{ .default.oslo.log.logging_debug_format_suffix | default "%(funcName)s %(pathname)s:%(lineno)d" }}

# Prefix each line of exception output with this format. (string
# value)
# from .default.oslo.log.logging_exception_prefix
{{ if not .default.oslo.log.logging_exception_prefix }}#{{ end }}logging_exception_prefix = {{ .default.oslo.log.logging_exception_prefix | default "%(asctime)s.%(msecs)03d %(process)d ERROR %(name)s %(instance)s" }}

# Defines the format string for %(user_identity)s that is used in
# logging_context_format_string. (string value)
# from .default.oslo.log.logging_user_identity_format
{{ if not .default.oslo.log.logging_user_identity_format }}#{{ end }}logging_user_identity_format = {{ .default.oslo.log.logging_user_identity_format | default "%(user)s %(tenant)s %(domain)s %(user_domain)s %(project_domain)s" }}

# List of package logging levels in logger=LEVEL pairs. This option is
# ignored if log_config_append is set. (list value)
# from .default.oslo.log.default_log_levels
{{ if not .default.oslo.log.default_log_levels }}#{{ end }}default_log_levels = {{ .default.oslo.log.default_log_levels | default "amqp=WARN,amqplib=WARN,boto=WARN,qpid=WARN,sqlalchemy=WARN,suds=INFO,oslo.messaging=INFO,iso8601=WARN,requests.packages.urllib3.connectionpool=WARN,urllib3.connectionpool=WARN,websocket=WARN,requests.packages.urllib3.util.retry=WARN,urllib3.util.retry=WARN,keystonemiddleware=WARN,routes.middleware=WARN,stevedore=WARN,taskflow=WARN,keystoneauth=WARN,oslo.cache=INFO,dogpile.core.dogpile=INFO" }}

# Enables or disables publication of error events. (boolean value)
# from .default.oslo.log.publish_errors
{{ if not .default.oslo.log.publish_errors }}#{{ end }}publish_errors = {{ .default.oslo.log.publish_errors | default "false" }}

# The format for an instance that is passed with the log message.
# (string value)
# from .default.oslo.log.instance_format
{{ if not .default.oslo.log.instance_format }}#{{ end }}instance_format = {{ .default.oslo.log.instance_format | default "\"[instance: %(uuid)s] \"" }}

# The format for an instance UUID that is passed with the log message.
# (string value)
# from .default.oslo.log.instance_uuid_format
{{ if not .default.oslo.log.instance_uuid_format }}#{{ end }}instance_uuid_format = {{ .default.oslo.log.instance_uuid_format | default "\"[instance: %(uuid)s] \"" }}

# Enables or disables fatal status of deprecations. (boolean value)
# from .default.oslo.log.fatal_deprecations
{{ if not .default.oslo.log.fatal_deprecations }}#{{ end }}fatal_deprecations = {{ .default.oslo.log.fatal_deprecations | default "false" }}

#
# From oslo.messaging
#

# Size of RPC connection pool. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_conn_pool_size
# from .default.oslo.messaging.rpc_conn_pool_size
{{ if not .default.oslo.messaging.rpc_conn_pool_size }}#{{ end }}rpc_conn_pool_size = {{ .default.oslo.messaging.rpc_conn_pool_size | default "30" }}

# The pool size limit for connections expiration policy (integer
# value)
# from .default.oslo.messaging.conn_pool_min_size
{{ if not .default.oslo.messaging.conn_pool_min_size }}#{{ end }}conn_pool_min_size = {{ .default.oslo.messaging.conn_pool_min_size | default "2" }}

# The time-to-live in sec of idle connections in the pool (integer
# value)
# from .default.oslo.messaging.conn_pool_ttl
{{ if not .default.oslo.messaging.conn_pool_ttl }}#{{ end }}conn_pool_ttl = {{ .default.oslo.messaging.conn_pool_ttl | default "1200" }}

# ZeroMQ bind address. Should be a wildcard (*), an ethernet
# interface, or IP. The "host" option should point or resolve to this
# address. (string value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_bind_address
# from .default.oslo.messaging.rpc_zmq_bind_address
{{ if not .default.oslo.messaging.rpc_zmq_bind_address }}#{{ end }}rpc_zmq_bind_address = {{ .default.oslo.messaging.rpc_zmq_bind_address | default "*" }}

# MatchMaker driver. (string value)
# Allowed values: redis, dummy
# Deprecated group/name - [DEFAULT]/rpc_zmq_matchmaker
# from .default.oslo.messaging.rpc_zmq_matchmaker
{{ if not .default.oslo.messaging.rpc_zmq_matchmaker }}#{{ end }}rpc_zmq_matchmaker = {{ .default.oslo.messaging.rpc_zmq_matchmaker | default "redis" }}

# Number of ZeroMQ contexts, defaults to 1. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_contexts
# from .default.oslo.messaging.rpc_zmq_contexts
{{ if not .default.oslo.messaging.rpc_zmq_contexts }}#{{ end }}rpc_zmq_contexts = {{ .default.oslo.messaging.rpc_zmq_contexts | default "1" }}

# Maximum number of ingress messages to locally buffer per topic.
# Default is unlimited. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_topic_backlog
# from .default.oslo.messaging.rpc_zmq_topic_backlog
{{ if not .default.oslo.messaging.rpc_zmq_topic_backlog }}#{{ end }}rpc_zmq_topic_backlog = {{ .default.oslo.messaging.rpc_zmq_topic_backlog | default "<None>" }}

# Directory for holding IPC sockets. (string value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_ipc_dir
# from .default.oslo.messaging.rpc_zmq_ipc_dir
{{ if not .default.oslo.messaging.rpc_zmq_ipc_dir }}#{{ end }}rpc_zmq_ipc_dir = {{ .default.oslo.messaging.rpc_zmq_ipc_dir | default "/var/run/openstack" }}

# Name of this node. Must be a valid hostname, FQDN, or IP address.
# Must match "host" option, if running Nova. (string value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_host
# from .default.oslo.messaging.rpc_zmq_host
{{ if not .default.oslo.messaging.rpc_zmq_host }}#{{ end }}rpc_zmq_host = {{ .default.oslo.messaging.rpc_zmq_host | default "localhost" }}

# Seconds to wait before a cast expires (TTL). The default value of -1
# specifies an infinite linger period. The value of 0 specifies no
# linger period. Pending messages shall be discarded immediately when
# the socket is closed. Only supported by impl_zmq. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_cast_timeout
# from .default.oslo.messaging.rpc_cast_timeout
{{ if not .default.oslo.messaging.rpc_cast_timeout }}#{{ end }}rpc_cast_timeout = {{ .default.oslo.messaging.rpc_cast_timeout | default "-1" }}

# The default number of seconds that poll should wait. Poll raises
# timeout exception when timeout expired. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_poll_timeout
# from .default.oslo.messaging.rpc_poll_timeout
{{ if not .default.oslo.messaging.rpc_poll_timeout }}#{{ end }}rpc_poll_timeout = {{ .default.oslo.messaging.rpc_poll_timeout | default "1" }}

# Expiration timeout in seconds of a name service record about
# existing target ( < 0 means no timeout). (integer value)
# Deprecated group/name - [DEFAULT]/zmq_target_expire
# from .default.oslo.messaging.zmq_target_expire
{{ if not .default.oslo.messaging.zmq_target_expire }}#{{ end }}zmq_target_expire = {{ .default.oslo.messaging.zmq_target_expire | default "300" }}

# Update period in seconds of a name service record about existing
# target. (integer value)
# Deprecated group/name - [DEFAULT]/zmq_target_update
# from .default.oslo.messaging.zmq_target_update
{{ if not .default.oslo.messaging.zmq_target_update }}#{{ end }}zmq_target_update = {{ .default.oslo.messaging.zmq_target_update | default "180" }}

# Use PUB/SUB pattern for fanout methods. PUB/SUB always uses proxy.
# (boolean value)
# Deprecated group/name - [DEFAULT]/use_pub_sub
# from .default.oslo.messaging.use_pub_sub
{{ if not .default.oslo.messaging.use_pub_sub }}#{{ end }}use_pub_sub = {{ .default.oslo.messaging.use_pub_sub | default "true" }}

# Use ROUTER remote proxy. (boolean value)
# Deprecated group/name - [DEFAULT]/use_router_proxy
# from .default.oslo.messaging.use_router_proxy
{{ if not .default.oslo.messaging.use_router_proxy }}#{{ end }}use_router_proxy = {{ .default.oslo.messaging.use_router_proxy | default "true" }}

# Minimal port number for random ports range. (port value)
# Minimum value: 0
# Maximum value: 65535
# Deprecated group/name - [DEFAULT]/rpc_zmq_min_port
# from .default.oslo.messaging.rpc_zmq_min_port
{{ if not .default.oslo.messaging.rpc_zmq_min_port }}#{{ end }}rpc_zmq_min_port = {{ .default.oslo.messaging.rpc_zmq_min_port | default "49153" }}

# Maximal port number for random ports range. (integer value)
# Minimum value: 1
# Maximum value: 65536
# Deprecated group/name - [DEFAULT]/rpc_zmq_max_port
# from .default.oslo.messaging.rpc_zmq_max_port
{{ if not .default.oslo.messaging.rpc_zmq_max_port }}#{{ end }}rpc_zmq_max_port = {{ .default.oslo.messaging.rpc_zmq_max_port | default "65536" }}

# Number of retries to find free port number before fail with
# ZMQBindError. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_bind_port_retries
# from .default.oslo.messaging.rpc_zmq_bind_port_retries
{{ if not .default.oslo.messaging.rpc_zmq_bind_port_retries }}#{{ end }}rpc_zmq_bind_port_retries = {{ .default.oslo.messaging.rpc_zmq_bind_port_retries | default "100" }}

# Default serialization mechanism for serializing/deserializing
# outgoing/incoming messages (string value)
# Allowed values: json, msgpack
# Deprecated group/name - [DEFAULT]/rpc_zmq_serialization
# from .default.oslo.messaging.rpc_zmq_serialization
{{ if not .default.oslo.messaging.rpc_zmq_serialization }}#{{ end }}rpc_zmq_serialization = {{ .default.oslo.messaging.rpc_zmq_serialization | default "json" }}

# This option configures round-robin mode in zmq socket. True means
# not keeping a queue when server side disconnects. False means to
# keep queue and messages even if server is disconnected, when the
# server appears we send all accumulated messages to it. (boolean
# value)
# from .default.oslo.messaging.zmq_immediate
{{ if not .default.oslo.messaging.zmq_immediate }}#{{ end }}zmq_immediate = {{ .default.oslo.messaging.zmq_immediate | default "false" }}

# Size of executor thread pool. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_thread_pool_size
# from .default.oslo.messaging.executor_thread_pool_size
{{ if not .default.oslo.messaging.executor_thread_pool_size }}#{{ end }}executor_thread_pool_size = {{ .default.oslo.messaging.executor_thread_pool_size | default "64" }}

# Seconds to wait for a response from a call. (integer value)
# from .default.oslo.messaging.rpc_response_timeout
{{ if not .default.oslo.messaging.rpc_response_timeout }}#{{ end }}rpc_response_timeout = {{ .default.oslo.messaging.rpc_response_timeout | default "60" }}

# A URL representing the messaging driver to use and its full
# configuration. (string value)
# from .default.oslo.messaging.transport_url
{{ if not .default.oslo.messaging.transport_url }}#{{ end }}transport_url = {{ .default.oslo.messaging.transport_url | default "<None>" }}

# DEPRECATED: The messaging driver to use, defaults to rabbit. Other
# drivers include amqp and zmq. (string value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .default.oslo.messaging.rpc_backend
{{ if not .default.oslo.messaging.rpc_backend }}#{{ end }}rpc_backend = {{ .default.oslo.messaging.rpc_backend | default "rabbit" }}

# The default exchange under which topics are scoped. May be
# overridden by an exchange name specified in the transport_url
# option. (string value)
# from .default.oslo.messaging.control_exchange
{{ if not .default.oslo.messaging.control_exchange }}#{{ end }}control_exchange = {{ .default.oslo.messaging.control_exchange | default "openstack" }}

#
# From oslo.service.periodic_task
#

# Some periodic tasks can be run in a separate process. Should we run
# them here? (boolean value)
# from .default.oslo.service.periodic_task.run_external_periodic_tasks
{{ if not .default.oslo.service.periodic_task.run_external_periodic_tasks }}#{{ end }}run_external_periodic_tasks = {{ .default.oslo.service.periodic_task.run_external_periodic_tasks | default "true" }}

#
# From oslo.service.service
#

# Enable eventlet backdoor.  Acceptable values are 0, <port>, and
# <start>:<end>, where 0 results in listening on a random tcp port
# number; <port> results in listening on the specified port number
# (and not enabling backdoor if that port is in use); and
# <start>:<end> results in listening on the smallest unused port
# number within the specified range of port numbers.  The chosen port
# is displayed in the service's log file. (string value)
# from .default.oslo.service.service.backdoor_port
{{ if not .default.oslo.service.service.backdoor_port }}#{{ end }}backdoor_port = {{ .default.oslo.service.service.backdoor_port | default "<None>" }}

# Enable eventlet backdoor, using the provided path as a unix socket
# that can receive connections. This option is mutually exclusive with
# 'backdoor_port' in that only one should be provided. If both are
# provided then the existence of this option overrides the usage of
# that option. (string value)
# from .default.oslo.service.service.backdoor_socket
{{ if not .default.oslo.service.service.backdoor_socket }}#{{ end }}backdoor_socket = {{ .default.oslo.service.service.backdoor_socket | default "<None>" }}

# Enables or disables logging values of all registered options when
# starting a service (at DEBUG level). (boolean value)
# from .default.oslo.service.service.log_options
{{ if not .default.oslo.service.service.log_options }}#{{ end }}log_options = {{ .default.oslo.service.service.log_options | default "true" }}

# Specify a timeout after which a gracefully shutdown server will
# exit. Zero value means endless wait. (integer value)
# from .default.oslo.service.service.graceful_shutdown_timeout
{{ if not .default.oslo.service.service.graceful_shutdown_timeout }}#{{ end }}graceful_shutdown_timeout = {{ .default.oslo.service.service.graceful_shutdown_timeout | default "60" }}

#
# From oslo.service.wsgi
#

# File name for the paste.deploy config for api service (string value)
# from .default.oslo.service.wsgi.api_paste_config
{{ if not .default.oslo.service.wsgi.api_paste_config }}#{{ end }}api_paste_config = {{ .default.oslo.service.wsgi.api_paste_config | default "api-paste.ini" }}

# A python format string that is used as the template to generate log
# lines. The following values can beformatted into it: client_ip,
# date_time, request_line, status_code, body_length, wall_seconds.
# (string value)
# from .default.oslo.service.wsgi.wsgi_log_format
{{ if not .default.oslo.service.wsgi.wsgi_log_format }}#{{ end }}wsgi_log_format = {{ .default.oslo.service.wsgi.wsgi_log_format | default "%(client_ip)s \"%(request_line)s\" status: %(status_code)s  len: %(body_length)s time: %(wall_seconds).7f" }}

# Sets the value of TCP_KEEPIDLE in seconds for each server socket.
# Not supported on OS X. (integer value)
# from .default.oslo.service.wsgi.tcp_keepidle
{{ if not .default.oslo.service.wsgi.tcp_keepidle }}#{{ end }}tcp_keepidle = {{ .default.oslo.service.wsgi.tcp_keepidle | default "600" }}

# Size of the pool of greenthreads used by wsgi (integer value)
# from .default.oslo.service.wsgi.wsgi_default_pool_size
{{ if not .default.oslo.service.wsgi.wsgi_default_pool_size }}#{{ end }}wsgi_default_pool_size = {{ .default.oslo.service.wsgi.wsgi_default_pool_size | default "100" }}

# Maximum line size of message headers to be accepted. max_header_line
# may need to be increased when using large tokens (typically those
# generated when keystone is configured to use PKI tokens with big
# service catalogs). (integer value)
# from .default.oslo.service.wsgi.max_header_line
{{ if not .default.oslo.service.wsgi.max_header_line }}#{{ end }}max_header_line = {{ .default.oslo.service.wsgi.max_header_line | default "16384" }}

# If False, closes the client socket connection explicitly. (boolean
# value)
# from .default.oslo.service.wsgi.wsgi_keep_alive
{{ if not .default.oslo.service.wsgi.wsgi_keep_alive }}#{{ end }}wsgi_keep_alive = {{ .default.oslo.service.wsgi.wsgi_keep_alive | default "true" }}

# Timeout for client connections' socket operations. If an incoming
# connection is idle for this number of seconds it will be closed. A
# value of '0' means wait forever. (integer value)
# from .default.oslo.service.wsgi.client_socket_timeout
{{ if not .default.oslo.service.wsgi.client_socket_timeout }}#{{ end }}client_socket_timeout = {{ .default.oslo.service.wsgi.client_socket_timeout | default "900" }}

{{ range $name, $options := .backends }}
[{{ $name }}]

#
# From cinder
#

# The flag of thin storage allocation. (boolean value)
# from $options.dsware_isthin
{{ if not $options.dsware_isthin }}#{{ end }}dsware_isthin = {{ $options.dsware_isthin | default "false" }}

# Fusionstorage manager ip addr for cinder-volume. (string value)
# from $options.dsware_manager
{{ if not $options.dsware_manager }}#{{ end }}dsware_manager = {{ $options.dsware_manager | default "" }}

# Fusionstorage agent ip addr range. (string value)
# from $options.fusionstorageagent
{{ if not $options.fusionstorageagent }}#{{ end }}fusionstorageagent = {{ $options.fusionstorageagent | default "" }}

# Pool type, like sata-2copy. (string value)
# from $options.pool_type
{{ if not $options.pool_type }}#{{ end }}pool_type = {{ $options.pool_type | default "default" }}

# Pool id permit to use. (list value)
# from $options.pool_id_filter
{{ if not $options.pool_id_filter }}#{{ end }}pool_id_filter = {{ $options.pool_id_filter | default "" }}

# Create clone volume timeout. (integer value)
# from $options.clone_volume_timeout
{{ if not $options.clone_volume_timeout }}#{{ end }}clone_volume_timeout = {{ $options.clone_volume_timeout | default "680" }}

# Backend override of host value. (string value)
# Deprecated group/name - [BACKEND]/host
# from $options.backend_host
{{ if not $options.backend_host }}#{{ end }}backend_host = {{ $options.backend_host | default "<None>" }}

# Management IP address of HNAS. This can be any IP in the admin
# address on HNAS or the SMU IP. (IP address value)
# from $options.hnas_mgmt_ip0
{{ if not $options.hnas_mgmt_ip0 }}#{{ end }}hnas_mgmt_ip0 = {{ $options.hnas_mgmt_ip0 | default "<None>" }}

# Command to communicate to HNAS. (string value)
# from $options.hnas_ssc_cmd
{{ if not $options.hnas_ssc_cmd }}#{{ end }}hnas_ssc_cmd = {{ $options.hnas_ssc_cmd | default "ssc" }}

# HNAS username. (string value)
# from $options.hnas_username
{{ if not $options.hnas_username }}#{{ end }}hnas_username = {{ $options.hnas_username | default "<None>" }}

# HNAS password. (string value)
# from $options.hnas_password
{{ if not $options.hnas_password }}#{{ end }}hnas_password = {{ $options.hnas_password | default "<None>" }}

# Port to be used for SSH authentication. (port value)
# Minimum value: 0
# Maximum value: 65535
# from $options.hnas_ssh_port
{{ if not $options.hnas_ssh_port }}#{{ end }}hnas_ssh_port = {{ $options.hnas_ssh_port | default "22" }}

# Path to the SSH private key used to authenticate in HNAS SMU.
# (string value)
# from $options.hnas_ssh_private_key
{{ if not $options.hnas_ssh_private_key }}#{{ end }}hnas_ssh_private_key = {{ $options.hnas_ssh_private_key | default "<None>" }}

# The IP of the HNAS cluster admin. Required only for HNAS multi-
# cluster setups. (string value)
# from $options.hnas_cluster_admin_ip0
{{ if not $options.hnas_cluster_admin_ip0 }}#{{ end }}hnas_cluster_admin_ip0 = {{ $options.hnas_cluster_admin_ip0 | default "<None>" }}

# Service 0 volume type (string value)
# from $options.hnas_svc0_volume_type
{{ if not $options.hnas_svc0_volume_type }}#{{ end }}hnas_svc0_volume_type = {{ $options.hnas_svc0_volume_type | default "<None>" }}

# Service 0 HDP (string value)
# from $options.hnas_svc0_hdp
{{ if not $options.hnas_svc0_hdp }}#{{ end }}hnas_svc0_hdp = {{ $options.hnas_svc0_hdp | default "<None>" }}

# Service 1 volume type (string value)
# from $options.hnas_svc1_volume_type
{{ if not $options.hnas_svc1_volume_type }}#{{ end }}hnas_svc1_volume_type = {{ $options.hnas_svc1_volume_type | default "<None>" }}

# Service 1 HDP (string value)
# from $options.hnas_svc1_hdp
{{ if not $options.hnas_svc1_hdp }}#{{ end }}hnas_svc1_hdp = {{ $options.hnas_svc1_hdp | default "<None>" }}

# Service 2 volume type (string value)
# from $options.hnas_svc2_volume_type
{{ if not $options.hnas_svc2_volume_type }}#{{ end }}hnas_svc2_volume_type = {{ $options.hnas_svc2_volume_type | default "<None>" }}

# Service 2 HDP (string value)
# from $options.hnas_svc2_hdp
{{ if not $options.hnas_svc2_hdp }}#{{ end }}hnas_svc2_hdp = {{ $options.hnas_svc2_hdp | default "<None>" }}

# Service 3 volume type (string value)
# from $options.hnas_svc3_volume_type
{{ if not $options.hnas_svc3_volume_type }}#{{ end }}hnas_svc3_volume_type = {{ $options.hnas_svc3_volume_type | default "<None>" }}

# Service 3 HDP (string value)
# from $options.hnas_svc3_hdp
{{ if not $options.hnas_svc3_hdp }}#{{ end }}hnas_svc3_hdp = {{ $options.hnas_svc3_hdp | default "<None>" }}

# File with the list of available smbfs shares. (string value)
# from $options.smbfs_shares_config
{{ if not $options.smbfs_shares_config }}#{{ end }}smbfs_shares_config = {{ $options.smbfs_shares_config | default "/etc/cinder/smbfs_shares" }}

# The path of the automatically generated file containing information
# about volume disk space allocation. (string value)
# from $options.smbfs_allocation_info_file_path
{{ if not $options.smbfs_allocation_info_file_path }}#{{ end }}smbfs_allocation_info_file_path = {{ $options.smbfs_allocation_info_file_path | default "$state_path/allocation_data" }}

# Default format that will be used when creating volumes if no volume
# format is specified. (string value)
# Allowed values: raw, qcow2, vhd, vhdx
# from $options.smbfs_default_volume_format
{{ if not $options.smbfs_default_volume_format }}#{{ end }}smbfs_default_volume_format = {{ $options.smbfs_default_volume_format | default "qcow2" }}

# Create volumes as sparsed files which take no space rather than
# regular files when using raw format, in which case volume creation
# takes lot of time. (boolean value)
# from $options.smbfs_sparsed_volumes
{{ if not $options.smbfs_sparsed_volumes }}#{{ end }}smbfs_sparsed_volumes = {{ $options.smbfs_sparsed_volumes | default "true" }}

# Percent of ACTUAL usage of the underlying volume before no new
# volumes can be allocated to the volume destination. (floating point
# value)
# from $options.smbfs_used_ratio
{{ if not $options.smbfs_used_ratio }}#{{ end }}smbfs_used_ratio = {{ $options.smbfs_used_ratio | default "0.95" }}

# This will compare the allocated to available space on the volume
# destination.  If the ratio exceeds this number, the destination will
# no longer be valid. (floating point value)
# from $options.smbfs_oversub_ratio
{{ if not $options.smbfs_oversub_ratio }}#{{ end }}smbfs_oversub_ratio = {{ $options.smbfs_oversub_ratio | default "1.0" }}

# Base dir containing mount points for smbfs shares. (string value)
# from $options.smbfs_mount_point_base
{{ if not $options.smbfs_mount_point_base }}#{{ end }}smbfs_mount_point_base = {{ $options.smbfs_mount_point_base | default "$state_path/mnt" }}

# Mount options passed to the smbfs client. See mount.cifs man page
# for details. (string value)
# from $options.smbfs_mount_options
{{ if not $options.smbfs_mount_options }}#{{ end }}smbfs_mount_options = {{ $options.smbfs_mount_options | default "noperm,file_mode=0775,dir_mode=0775" }}

# Use thin provisioning for SAN volumes? (boolean value)
# from $options.san_thin_provision
{{ if not $options.san_thin_provision }}#{{ end }}san_thin_provision = {{ $options.san_thin_provision | default "true" }}

# IP address of SAN controller (string value)
# from $options.san_ip
{{ if not $options.san_ip }}#{{ end }}san_ip = {{ $options.san_ip | default "" }}

# Username for SAN controller (string value)
# from $options.san_login
{{ if not $options.san_login }}#{{ end }}san_login = {{ $options.san_login | default "admin" }}

# Password for SAN controller (string value)
# from $options.san_password
{{ if not $options.san_password }}#{{ end }}san_password = {{ $options.san_password | default "" }}

# Filename of private key to use for SSH authentication (string value)
# from $options.san_private_key
{{ if not $options.san_private_key }}#{{ end }}san_private_key = {{ $options.san_private_key | default "" }}

# Cluster name to use for creating volumes (string value)
# from $options.san_clustername
{{ if not $options.san_clustername }}#{{ end }}san_clustername = {{ $options.san_clustername | default "" }}

# SSH port to use with SAN (port value)
# Minimum value: 0
# Maximum value: 65535
# from $options.san_ssh_port
{{ if not $options.san_ssh_port }}#{{ end }}san_ssh_port = {{ $options.san_ssh_port | default "22" }}

# Execute commands locally instead of over SSH; use if the volume
# service is running on the SAN device (boolean value)
# from $options.san_is_local
{{ if not $options.san_is_local }}#{{ end }}san_is_local = {{ $options.san_is_local | default "false" }}

# SSH connection timeout in seconds (integer value)
# from $options.ssh_conn_timeout
{{ if not $options.ssh_conn_timeout }}#{{ end }}ssh_conn_timeout = {{ $options.ssh_conn_timeout | default "30" }}

# Minimum ssh connections in the pool (integer value)
# from $options.ssh_min_pool_conn
{{ if not $options.ssh_min_pool_conn }}#{{ end }}ssh_min_pool_conn = {{ $options.ssh_min_pool_conn | default "1" }}

# Maximum ssh connections in the pool (integer value)
# from $options.ssh_max_pool_conn
{{ if not $options.ssh_max_pool_conn }}#{{ end }}ssh_max_pool_conn = {{ $options.ssh_max_pool_conn | default "5" }}

# DEPRECATED: Legacy configuration file for HNAS NFS Cinder plugin.
# This is not needed if you fill all configuration on cinder.conf
# (string value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# from $options.hds_hnas_nfs_config_file
{{ if not $options.hds_hnas_nfs_config_file }}#{{ end }}hds_hnas_nfs_config_file = {{ $options.hds_hnas_nfs_config_file | default "/opt/hds/hnas/cinder_nfs_conf.xml" }}

# The storage family type used on the storage system; valid values are
# ontap_7mode for using Data ONTAP operating in 7-Mode, ontap_cluster
# for using clustered Data ONTAP, or eseries for using E-Series.
# (string value)
# Allowed values: ontap_7mode, ontap_cluster, eseries
# from $options.netapp_storage_family
{{ if not $options.netapp_storage_family }}#{{ end }}netapp_storage_family = {{ $options.netapp_storage_family | default "ontap_cluster" }}

# The storage protocol to be used on the data path with the storage
# system. (string value)
# Allowed values: iscsi, fc, nfs
# from $options.netapp_storage_protocol
{{ if not $options.netapp_storage_protocol }}#{{ end }}netapp_storage_protocol = {{ $options.netapp_storage_protocol | default "<None>" }}

# The hostname (or IP address) for the storage system or proxy server.
# (string value)
# from $options.netapp_server_hostname
{{ if not $options.netapp_server_hostname }}#{{ end }}netapp_server_hostname = {{ $options.netapp_server_hostname | default "<None>" }}

# The TCP port to use for communication with the storage system or
# proxy server. If not specified, Data ONTAP drivers will use 80 for
# HTTP and 443 for HTTPS; E-Series will use 8080 for HTTP and 8443 for
# HTTPS. (integer value)
# from $options.netapp_server_port
{{ if not $options.netapp_server_port }}#{{ end }}netapp_server_port = {{ $options.netapp_server_port | default "<None>" }}

# The transport protocol used when communicating with the storage
# system or proxy server. (string value)
# Allowed values: http, https
# from $options.netapp_transport_type
{{ if not $options.netapp_transport_type }}#{{ end }}netapp_transport_type = {{ $options.netapp_transport_type | default "http" }}

# Administrative user account name used to access the storage system
# or proxy server. (string value)
# from $options.netapp_login
{{ if not $options.netapp_login }}#{{ end }}netapp_login = {{ $options.netapp_login | default "<None>" }}

# Password for the administrative user account specified in the
# netapp_login option. (string value)
# from $options.netapp_password
{{ if not $options.netapp_password }}#{{ end }}netapp_password = {{ $options.netapp_password | default "<None>" }}

# This option specifies the virtual storage server (Vserver) name on
# the storage cluster on which provisioning of block storage volumes
# should occur. (string value)
# from $options.netapp_vserver
{{ if not $options.netapp_vserver }}#{{ end }}netapp_vserver = {{ $options.netapp_vserver | default "<None>" }}

# The vFiler unit on which provisioning of block storage volumes will
# be done. This option is only used by the driver when connecting to
# an instance with a storage family of Data ONTAP operating in 7-Mode.
# Only use this option when utilizing the MultiStore feature on the
# NetApp storage system. (string value)
# from $options.netapp_vfiler
{{ if not $options.netapp_vfiler }}#{{ end }}netapp_vfiler = {{ $options.netapp_vfiler | default "<None>" }}

# The name of the config.conf stanza for a Data ONTAP (7-mode) HA
# partner.  This option is only used by the driver when connecting to
# an instance with a storage family of Data ONTAP operating in 7-Mode,
# and it is required if the storage protocol selected is FC. (string
# value)
# from $options.netapp_partner_backend_name
{{ if not $options.netapp_partner_backend_name }}#{{ end }}netapp_partner_backend_name = {{ $options.netapp_partner_backend_name | default "<None>" }}

# The quantity to be multiplied by the requested volume size to ensure
# enough space is available on the virtual storage server (Vserver) to
# fulfill the volume creation request.  Note: this option is
# deprecated and will be removed in favor of "reserved_percentage" in
# the Mitaka release. (floating point value)
# from $options.netapp_size_multiplier
{{ if not $options.netapp_size_multiplier }}#{{ end }}netapp_size_multiplier = {{ $options.netapp_size_multiplier | default "1.2" }}

# This option determines if storage space is reserved for LUN
# allocation. If enabled, LUNs are thick provisioned. If space
# reservation is disabled, storage space is allocated on demand.
# (string value)
# Allowed values: enabled, disabled
# from $options.netapp_lun_space_reservation
{{ if not $options.netapp_lun_space_reservation }}#{{ end }}netapp_lun_space_reservation = {{ $options.netapp_lun_space_reservation | default "enabled" }}

# If the percentage of available space for an NFS share has dropped
# below the value specified by this option, the NFS image cache will
# be cleaned. (integer value)
# from $options.thres_avl_size_perc_start
{{ if not $options.thres_avl_size_perc_start }}#{{ end }}thres_avl_size_perc_start = {{ $options.thres_avl_size_perc_start | default "20" }}

# When the percentage of available space on an NFS share has reached
# the percentage specified by this option, the driver will stop
# clearing files from the NFS image cache that have not been accessed
# in the last M minutes, where M is the value of the
# expiry_thres_minutes configuration option. (integer value)
# from $options.thres_avl_size_perc_stop
{{ if not $options.thres_avl_size_perc_stop }}#{{ end }}thres_avl_size_perc_stop = {{ $options.thres_avl_size_perc_stop | default "60" }}

# This option specifies the threshold for last access time for images
# in the NFS image cache. When a cache cleaning cycle begins, images
# in the cache that have not been accessed in the last M minutes,
# where M is the value of this parameter, will be deleted from the
# cache to create free space on the NFS share. (integer value)
# from $options.expiry_thres_minutes
{{ if not $options.expiry_thres_minutes }}#{{ end }}expiry_thres_minutes = {{ $options.expiry_thres_minutes | default "720" }}

# This option is used to specify the path to the E-Series proxy
# application on a proxy server. The value is combined with the value
# of the netapp_transport_type, netapp_server_hostname, and
# netapp_server_port options to create the URL used by the driver to
# connect to the proxy application. (string value)
# from $options.netapp_webservice_path
{{ if not $options.netapp_webservice_path }}#{{ end }}netapp_webservice_path = {{ $options.netapp_webservice_path | default "/devmgr/v2" }}

# This option is only utilized when the storage family is configured
# to eseries. This option is used to restrict provisioning to the
# specified controllers. Specify the value of this option to be a
# comma separated list of controller hostnames or IP addresses to be
# used for provisioning. (string value)
# from $options.netapp_controller_ips
{{ if not $options.netapp_controller_ips }}#{{ end }}netapp_controller_ips = {{ $options.netapp_controller_ips | default "<None>" }}

# Password for the NetApp E-Series storage array. (string value)
# from $options.netapp_sa_password
{{ if not $options.netapp_sa_password }}#{{ end }}netapp_sa_password = {{ $options.netapp_sa_password | default "<None>" }}

# This option specifies whether the driver should allow operations
# that require multiple attachments to a volume. An example would be
# live migration of servers that have volumes attached. When enabled,
# this backend is limited to 256 total volumes in order to guarantee
# volumes can be accessed by more than one host. (boolean value)
# from $options.netapp_enable_multiattach
{{ if not $options.netapp_enable_multiattach }}#{{ end }}netapp_enable_multiattach = {{ $options.netapp_enable_multiattach | default "false" }}

# This option specifies the path of the NetApp copy offload tool
# binary. Ensure that the binary has execute permissions set which
# allow the effective user of the cinder-volume process to execute the
# file. (string value)
# from $options.netapp_copyoffload_tool_path
{{ if not $options.netapp_copyoffload_tool_path }}#{{ end }}netapp_copyoffload_tool_path = {{ $options.netapp_copyoffload_tool_path | default "<None>" }}

# This option defines the type of operating system that will access a
# LUN exported from Data ONTAP; it is assigned to the LUN at the time
# it is created. (string value)
# from $options.netapp_lun_ostype
{{ if not $options.netapp_lun_ostype }}#{{ end }}netapp_lun_ostype = {{ $options.netapp_lun_ostype | default "<None>" }}

# This option defines the type of operating system for all initiators
# that can access a LUN. This information is used when mapping LUNs to
# individual hosts or groups of hosts. (string value)
# Deprecated group/name - [BACKEND]/netapp_eseries_host_type
# from $options.netapp_host_type
{{ if not $options.netapp_host_type }}#{{ end }}netapp_host_type = {{ $options.netapp_host_type | default "<None>" }}

# This option is used to restrict provisioning to the specified pools.
# Specify the value of this option to be a regular expression which
# will be applied to the names of objects from the storage backend
# which represent pools in Cinder. This option is only utilized when
# the storage protocol is configured to use iSCSI or FC. (string
# value)
# Deprecated group/name - [BACKEND]/netapp_volume_list
# Deprecated group/name - [BACKEND]/netapp_storage_pools
# from $options.netapp_pool_name_search_pattern
{{ if not $options.netapp_pool_name_search_pattern }}#{{ end }}netapp_pool_name_search_pattern = {{ $options.netapp_pool_name_search_pattern | default "(.+)" }}

# Multi opt of dictionaries to represent the aggregate mapping between
# source and destination back ends when using whole back end
# replication. For every source aggregate associated with a cinder
# pool (NetApp FlexVol), you would need to specify the destination
# aggregate on the replication target device. A replication target
# device is configured with the configuration option
# replication_device. Specify this option as many times as you have
# replication devices. Each entry takes the standard dict config form:
# netapp_replication_aggregate_map =
# backend_id:<name_of_replication_device_section>,src_aggr_name1:dest_aggr_name1,src_aggr_name2:dest_aggr_name2,...
# (dict value)
# from $options.netapp_replication_aggregate_map (multiopt)
{{ if not $options.netapp_replication_aggregate_map }}#netapp_replication_aggregate_map = {{ $options.netapp_replication_aggregate_map | default "<None>" }}{{ else }}{{ range $options.netapp_replication_aggregate_map }}netapp_replication_aggregate_map = {{ . }}{{ end }}{{ end }}

# The maximum time in seconds to wait for existing SnapMirror
# transfers to complete before aborting during a failover. (integer
# value)
# Minimum value: 0
# from $options.netapp_snapmirror_quiesce_timeout
{{ if not $options.netapp_snapmirror_quiesce_timeout }}#{{ end }}netapp_snapmirror_quiesce_timeout = {{ $options.netapp_snapmirror_quiesce_timeout | default "3600" }}

# Configure CHAP authentication for iSCSI connections (Default:
# Enabled) (boolean value)
# from $options.storwize_svc_iscsi_chap_enabled
{{ if not $options.storwize_svc_iscsi_chap_enabled }}#{{ end }}storwize_svc_iscsi_chap_enabled = {{ $options.storwize_svc_iscsi_chap_enabled | default "true" }}

# Rest Gateway IP or FQDN for Scaleio (string value)
# from $options.coprhd_scaleio_rest_gateway_host
{{ if not $options.coprhd_scaleio_rest_gateway_host }}#{{ end }}coprhd_scaleio_rest_gateway_host = {{ $options.coprhd_scaleio_rest_gateway_host | default "None" }}

# Rest Gateway Port for Scaleio (port value)
# Minimum value: 0
# Maximum value: 65535
# from $options.coprhd_scaleio_rest_gateway_port
{{ if not $options.coprhd_scaleio_rest_gateway_port }}#{{ end }}coprhd_scaleio_rest_gateway_port = {{ $options.coprhd_scaleio_rest_gateway_port | default "4984" }}

# Username for Rest Gateway (string value)
# from $options.coprhd_scaleio_rest_server_username
{{ if not $options.coprhd_scaleio_rest_server_username }}#{{ end }}coprhd_scaleio_rest_server_username = {{ $options.coprhd_scaleio_rest_server_username | default "<None>" }}

# Rest Gateway Password (string value)
# from $options.coprhd_scaleio_rest_server_password
{{ if not $options.coprhd_scaleio_rest_server_password }}#{{ end }}coprhd_scaleio_rest_server_password = {{ $options.coprhd_scaleio_rest_server_password | default "<None>" }}

# verify server certificate (boolean value)
# from $options.scaleio_verify_server_certificate
{{ if not $options.scaleio_verify_server_certificate }}#{{ end }}scaleio_verify_server_certificate = {{ $options.scaleio_verify_server_certificate | default "false" }}

# Server certificate path (string value)
# from $options.scaleio_server_certificate_path
{{ if not $options.scaleio_server_certificate_path }}#{{ end }}scaleio_server_certificate_path = {{ $options.scaleio_server_certificate_path | default "<None>" }}

# config file for cinder eternus_dx volume driver (string value)
# from $options.cinder_eternus_config_file
{{ if not $options.cinder_eternus_config_file }}#{{ end }}cinder_eternus_config_file = {{ $options.cinder_eternus_config_file | default "/etc/cinder/cinder_fujitsu_eternus_dx.xml" }}

# Specifies the path of the GPFS directory where Block Storage volume
# and snapshot files are stored. (string value)
# from $options.gpfs_mount_point_base
{{ if not $options.gpfs_mount_point_base }}#{{ end }}gpfs_mount_point_base = {{ $options.gpfs_mount_point_base | default "<None>" }}

# Specifies the path of the Image service repository in GPFS.  Leave
# undefined if not storing images in GPFS. (string value)
# from $options.gpfs_images_dir
{{ if not $options.gpfs_images_dir }}#{{ end }}gpfs_images_dir = {{ $options.gpfs_images_dir | default "<None>" }}

# Specifies the type of image copy to be used.  Set this when the
# Image service repository also uses GPFS so that image files can be
# transferred efficiently from the Image service to the Block Storage
# service. There are two valid values: "copy" specifies that a full
# copy of the image is made; "copy_on_write" specifies that copy-on-
# write optimization strategy is used and unmodified blocks of the
# image file are shared efficiently. (string value)
# Allowed values: copy, copy_on_write, <None>
# from $options.gpfs_images_share_mode
{{ if not $options.gpfs_images_share_mode }}#{{ end }}gpfs_images_share_mode = {{ $options.gpfs_images_share_mode | default "<None>" }}

# Specifies an upper limit on the number of indirections required to
# reach a specific block due to snapshots or clones.  A lengthy chain
# of copy-on-write snapshots or clones can have a negative impact on
# performance, but improves space utilization.  0 indicates unlimited
# clone depth. (integer value)
# from $options.gpfs_max_clone_depth
{{ if not $options.gpfs_max_clone_depth }}#{{ end }}gpfs_max_clone_depth = {{ $options.gpfs_max_clone_depth | default "0" }}

# Specifies that volumes are created as sparse files which initially
# consume no space. If set to False, the volume is created as a fully
# allocated file, in which case, creation may take a significantly
# longer time. (boolean value)
# from $options.gpfs_sparse_volumes
{{ if not $options.gpfs_sparse_volumes }}#{{ end }}gpfs_sparse_volumes = {{ $options.gpfs_sparse_volumes | default "true" }}

# Specifies the storage pool that volumes are assigned to. By default,
# the system storage pool is used. (string value)
# from $options.gpfs_storage_pool
{{ if not $options.gpfs_storage_pool }}#{{ end }}gpfs_storage_pool = {{ $options.gpfs_storage_pool | default "system" }}

# Main controller IP. (IP address value)
# from $options.zteControllerIP0
{{ if not $options.zteControllerIP0 }}#{{ end }}zteControllerIP0 = {{ $options.zteControllerIP0 | default "<None>" }}

# Slave controller IP. (IP address value)
# from $options.zteControllerIP1
{{ if not $options.zteControllerIP1 }}#{{ end }}zteControllerIP1 = {{ $options.zteControllerIP1 | default "<None>" }}

# Local IP. (IP address value)
# from $options.zteLocalIP
{{ if not $options.zteLocalIP }}#{{ end }}zteLocalIP = {{ $options.zteLocalIP | default "<None>" }}

# User name. (string value)
# from $options.zteUserName
{{ if not $options.zteUserName }}#{{ end }}zteUserName = {{ $options.zteUserName | default "<None>" }}

# User password. (string value)
# from $options.zteUserPassword
{{ if not $options.zteUserPassword }}#{{ end }}zteUserPassword = {{ $options.zteUserPassword | default "<None>" }}

# Virtual block size of pool. Unit : KB. Valid value :  4,  8, 16, 32,
# 64, 128, 256, 512.  (integer value)
# from $options.zteChunkSize
{{ if not $options.zteChunkSize }}#{{ end }}zteChunkSize = {{ $options.zteChunkSize | default "4" }}

# Cache readahead size. (integer value)
# from $options.zteAheadReadSize
{{ if not $options.zteAheadReadSize }}#{{ end }}zteAheadReadSize = {{ $options.zteAheadReadSize | default "8" }}

# Cache policy. 0, Write Back; 1, Write Through. (integer value)
# from $options.zteCachePolicy
{{ if not $options.zteCachePolicy }}#{{ end }}zteCachePolicy = {{ $options.zteCachePolicy | default "1" }}

# SSD cache switch. 0, OFF; 1, ON. (integer value)
# from $options.zteSSDCacheSwitch
{{ if not $options.zteSSDCacheSwitch }}#{{ end }}zteSSDCacheSwitch = {{ $options.zteSSDCacheSwitch | default "1" }}

# Pool name list. (list value)
# from $options.zteStoragePool
{{ if not $options.zteStoragePool }}#{{ end }}zteStoragePool = {{ $options.zteStoragePool | default "" }}

# Pool volume allocated policy. 0, Auto; 1, High Performance Tier
# First; 2, Performance Tier First; 3, Capacity Tier First. (integer
# value)
# from $options.ztePoolVoAllocatedPolicy
{{ if not $options.ztePoolVoAllocatedPolicy }}#{{ end }}ztePoolVoAllocatedPolicy = {{ $options.ztePoolVoAllocatedPolicy | default "0" }}

# Pool volume move policy.0, Auto; 1, Highest Available; 2, Lowest
# Available; 3, No Relocation. (integer value)
# from $options.ztePoolVolMovePolicy
{{ if not $options.ztePoolVolMovePolicy }}#{{ end }}ztePoolVolMovePolicy = {{ $options.ztePoolVolMovePolicy | default "0" }}

# Whether it is a thin volume. (integer value)
# from $options.ztePoolVolIsThin
{{ if not $options.ztePoolVolIsThin }}#{{ end }}ztePoolVolIsThin = {{ $options.ztePoolVolIsThin | default "False" }}

# Pool volume init allocated Capacity.Unit : KB.  (integer value)
# from $options.ztePoolVolInitAllocatedCapacity
{{ if not $options.ztePoolVolInitAllocatedCapacity }}#{{ end }}ztePoolVolInitAllocatedCapacity = {{ $options.ztePoolVolInitAllocatedCapacity | default "0" }}

# Pool volume alarm threshold. [0, 100] (integer value)
# from $options.ztePoolVolAlarmThreshold
{{ if not $options.ztePoolVolAlarmThreshold }}#{{ end }}ztePoolVolAlarmThreshold = {{ $options.ztePoolVolAlarmThreshold | default "0" }}

# Pool volume alarm stop allocated flag. (integer value)
# from $options.ztePoolVolAlarmStopAllocatedFlag
{{ if not $options.ztePoolVolAlarmStopAllocatedFlag }}#{{ end }}ztePoolVolAlarmStopAllocatedFlag = {{ $options.ztePoolVolAlarmStopAllocatedFlag | default "0" }}

# Global backend request timeout, in seconds. (integer value)
# from $options.violin_request_timeout
{{ if not $options.violin_request_timeout }}#{{ end }}violin_request_timeout = {{ $options.violin_request_timeout | default "300" }}

# Storage pools to be used to setup dedup luns only.(Comma separated
# list) (list value)
# from $options.violin_dedup_only_pools
{{ if not $options.violin_dedup_only_pools }}#{{ end }}violin_dedup_only_pools = {{ $options.violin_dedup_only_pools | default "" }}

# Storage pools capable of dedup and other luns.(Comma separated list)
# (list value)
# from $options.violin_dedup_capable_pools
{{ if not $options.violin_dedup_capable_pools }}#{{ end }}violin_dedup_capable_pools = {{ $options.violin_dedup_capable_pools | default "" }}

# Method of choosing a storage pool for a lun. (string value)
# Allowed values: random, largest, smallest
# from $options.violin_pool_allocation_method
{{ if not $options.violin_pool_allocation_method }}#{{ end }}violin_pool_allocation_method = {{ $options.violin_pool_allocation_method | default "random" }}

# Target iSCSI addresses to use.(Comma separated list) (list value)
# from $options.violin_iscsi_target_ips
{{ if not $options.violin_iscsi_target_ips }}#{{ end }}violin_iscsi_target_ips = {{ $options.violin_iscsi_target_ips | default "" }}

# IP address of Nexenta SA (string value)
# from $options.nexenta_host
{{ if not $options.nexenta_host }}#{{ end }}nexenta_host = {{ $options.nexenta_host | default "" }}

# HTTP port to connect to Nexenta REST API server (integer value)
# from $options.nexenta_rest_port
{{ if not $options.nexenta_rest_port }}#{{ end }}nexenta_rest_port = {{ $options.nexenta_rest_port | default "8080" }}

# Use http or https for REST connection (default auto) (string value)
# Allowed values: http, https, auto
# from $options.nexenta_rest_protocol
{{ if not $options.nexenta_rest_protocol }}#{{ end }}nexenta_rest_protocol = {{ $options.nexenta_rest_protocol | default "auto" }}

# User name to connect to Nexenta SA (string value)
# from $options.nexenta_user
{{ if not $options.nexenta_user }}#{{ end }}nexenta_user = {{ $options.nexenta_user | default "admin" }}

# Password to connect to Nexenta SA (string value)
# from $options.nexenta_password
{{ if not $options.nexenta_password }}#{{ end }}nexenta_password = {{ $options.nexenta_password | default "nexenta" }}

# Nexenta target portal port (integer value)
# from $options.nexenta_iscsi_target_portal_port
{{ if not $options.nexenta_iscsi_target_portal_port }}#{{ end }}nexenta_iscsi_target_portal_port = {{ $options.nexenta_iscsi_target_portal_port | default "3260" }}

# SA Pool that holds all volumes (string value)
# from $options.nexenta_volume
{{ if not $options.nexenta_volume }}#{{ end }}nexenta_volume = {{ $options.nexenta_volume | default "cinder" }}

# IQN prefix for iSCSI targets (string value)
# from $options.nexenta_target_prefix
{{ if not $options.nexenta_target_prefix }}#{{ end }}nexenta_target_prefix = {{ $options.nexenta_target_prefix | default "iqn.1986-03.com.sun:02:cinder-" }}

# Prefix for iSCSI target groups on SA (string value)
# from $options.nexenta_target_group_prefix
{{ if not $options.nexenta_target_group_prefix }}#{{ end }}nexenta_target_group_prefix = {{ $options.nexenta_target_group_prefix | default "cinder/" }}

# Volume group for ns5 (string value)
# from $options.nexenta_volume_group
{{ if not $options.nexenta_volume_group }}#{{ end }}nexenta_volume_group = {{ $options.nexenta_volume_group | default "iscsi" }}

# Compression value for new ZFS folders. (string value)
# Allowed values: on, off, gzip, gzip-1, gzip-2, gzip-3, gzip-4, gzip-5, gzip-6, gzip-7, gzip-8, gzip-9, lzjb, zle, lz4
# from $options.nexenta_dataset_compression
{{ if not $options.nexenta_dataset_compression }}#{{ end }}nexenta_dataset_compression = {{ $options.nexenta_dataset_compression | default "on" }}

# Deduplication value for new ZFS folders. (string value)
# Allowed values: on, off, sha256, verify, sha256, verify
# from $options.nexenta_dataset_dedup
{{ if not $options.nexenta_dataset_dedup }}#{{ end }}nexenta_dataset_dedup = {{ $options.nexenta_dataset_dedup | default "off" }}

# Human-readable description for the folder. (string value)
# from $options.nexenta_dataset_description
{{ if not $options.nexenta_dataset_description }}#{{ end }}nexenta_dataset_description = {{ $options.nexenta_dataset_description | default "" }}

# Block size for datasets (integer value)
# from $options.nexenta_blocksize
{{ if not $options.nexenta_blocksize }}#{{ end }}nexenta_blocksize = {{ $options.nexenta_blocksize | default "4096" }}

# Block size for datasets (integer value)
# from $options.nexenta_ns5_blocksize
{{ if not $options.nexenta_ns5_blocksize }}#{{ end }}nexenta_ns5_blocksize = {{ $options.nexenta_ns5_blocksize | default "32" }}

# Enables or disables the creation of sparse datasets (boolean value)
# from $options.nexenta_sparse
{{ if not $options.nexenta_sparse }}#{{ end }}nexenta_sparse = {{ $options.nexenta_sparse | default "false" }}

# File with the list of available nfs shares (string value)
# from $options.nexenta_shares_config
{{ if not $options.nexenta_shares_config }}#{{ end }}nexenta_shares_config = {{ $options.nexenta_shares_config | default "/etc/cinder/nfs_shares" }}

# Base directory that contains NFS share mount points (string value)
# from $options.nexenta_mount_point_base
{{ if not $options.nexenta_mount_point_base }}#{{ end }}nexenta_mount_point_base = {{ $options.nexenta_mount_point_base | default "$state_path/mnt" }}

# Enables or disables the creation of volumes as sparsed files that
# take no space. If disabled (False), volume is created as a regular
# file, which takes a long time. (boolean value)
# from $options.nexenta_sparsed_volumes
{{ if not $options.nexenta_sparsed_volumes }}#{{ end }}nexenta_sparsed_volumes = {{ $options.nexenta_sparsed_volumes | default "true" }}

# If set True cache NexentaStor appliance volroot option value.
# (boolean value)
# from $options.nexenta_nms_cache_volroot
{{ if not $options.nexenta_nms_cache_volroot }}#{{ end }}nexenta_nms_cache_volroot = {{ $options.nexenta_nms_cache_volroot | default "true" }}

# Enable stream compression, level 1..9. 1 - gives best speed; 9 -
# gives best compression. (integer value)
# from $options.nexenta_rrmgr_compression
{{ if not $options.nexenta_rrmgr_compression }}#{{ end }}nexenta_rrmgr_compression = {{ $options.nexenta_rrmgr_compression | default "0" }}

# TCP Buffer size in KiloBytes. (integer value)
# from $options.nexenta_rrmgr_tcp_buf_size
{{ if not $options.nexenta_rrmgr_tcp_buf_size }}#{{ end }}nexenta_rrmgr_tcp_buf_size = {{ $options.nexenta_rrmgr_tcp_buf_size | default "4096" }}

# Number of TCP connections. (integer value)
# from $options.nexenta_rrmgr_connections
{{ if not $options.nexenta_rrmgr_connections }}#{{ end }}nexenta_rrmgr_connections = {{ $options.nexenta_rrmgr_connections | default "2" }}

# NexentaEdge logical path of directory to store symbolic links to
# NBDs (string value)
# from $options.nexenta_nbd_symlinks_dir
{{ if not $options.nexenta_nbd_symlinks_dir }}#{{ end }}nexenta_nbd_symlinks_dir = {{ $options.nexenta_nbd_symlinks_dir | default "/dev/disk/by-path" }}

# IP address of NexentaEdge management REST API endpoint (string
# value)
# from $options.nexenta_rest_address
{{ if not $options.nexenta_rest_address }}#{{ end }}nexenta_rest_address = {{ $options.nexenta_rest_address | default "" }}

# User name to connect to NexentaEdge (string value)
# from $options.nexenta_rest_user
{{ if not $options.nexenta_rest_user }}#{{ end }}nexenta_rest_user = {{ $options.nexenta_rest_user | default "admin" }}

# Password to connect to NexentaEdge (string value)
# from $options.nexenta_rest_password
{{ if not $options.nexenta_rest_password }}#{{ end }}nexenta_rest_password = {{ $options.nexenta_rest_password | default "nexenta" }}

# NexentaEdge logical path of bucket for LUNs (string value)
# from $options.nexenta_lun_container
{{ if not $options.nexenta_lun_container }}#{{ end }}nexenta_lun_container = {{ $options.nexenta_lun_container | default "" }}

# NexentaEdge iSCSI service name (string value)
# from $options.nexenta_iscsi_service
{{ if not $options.nexenta_iscsi_service }}#{{ end }}nexenta_iscsi_service = {{ $options.nexenta_iscsi_service | default "" }}

# NexentaEdge iSCSI Gateway client address for non-VIP service (string
# value)
# from $options.nexenta_client_address
{{ if not $options.nexenta_client_address }}#{{ end }}nexenta_client_address = {{ $options.nexenta_client_address | default "" }}

# NexentaEdge iSCSI LUN object chunk size (integer value)
# from $options.nexenta_chunksize
{{ if not $options.nexenta_chunksize }}#{{ end }}nexenta_chunksize = {{ $options.nexenta_chunksize | default "32768" }}

# IP address of sheep daemon. (string value)
# from $options.sheepdog_store_address
{{ if not $options.sheepdog_store_address }}#{{ end }}sheepdog_store_address = {{ $options.sheepdog_store_address | default "127.0.0.1" }}

# Port of sheep daemon. (port value)
# Minimum value: 0
# Maximum value: 65535
# from $options.sheepdog_store_port
{{ if not $options.sheepdog_store_port }}#{{ end }}sheepdog_store_port = {{ $options.sheepdog_store_port | default "7000" }}

# Set 512 byte emulation on volume creation;  (boolean value)
# from $options.sf_emulate_512
{{ if not $options.sf_emulate_512 }}#{{ end }}sf_emulate_512 = {{ $options.sf_emulate_512 | default "true" }}

# Allow tenants to specify QOS on create (boolean value)
# from $options.sf_allow_tenant_qos
{{ if not $options.sf_allow_tenant_qos }}#{{ end }}sf_allow_tenant_qos = {{ $options.sf_allow_tenant_qos | default "false" }}

# Create SolidFire accounts with this prefix. Any string can be used
# here, but the string "hostname" is special and will create a prefix
# using the cinder node hostname (previous default behavior).  The
# default is NO prefix. (string value)
# from $options.sf_account_prefix
{{ if not $options.sf_account_prefix }}#{{ end }}sf_account_prefix = {{ $options.sf_account_prefix | default "<None>" }}

# Create SolidFire volumes with this prefix. Volume names are of the
# form <sf_volume_prefix><cinder-volume-id>.  The default is to use a
# prefix of 'UUID-'. (string value)
# from $options.sf_volume_prefix
{{ if not $options.sf_volume_prefix }}#{{ end }}sf_volume_prefix = {{ $options.sf_volume_prefix | default "UUID-" }}

# Account name on the SolidFire Cluster to use as owner of
# template/cache volumes (created if does not exist). (string value)
# from $options.sf_template_account_name
{{ if not $options.sf_template_account_name }}#{{ end }}sf_template_account_name = {{ $options.sf_template_account_name | default "openstack-vtemplate" }}

# Create an internal cache of copy of images when a bootable volume is
# created to eliminate fetch from glance and qemu-conversion on
# subsequent calls. (boolean value)
# from $options.sf_allow_template_caching
{{ if not $options.sf_allow_template_caching }}#{{ end }}sf_allow_template_caching = {{ $options.sf_allow_template_caching | default "true" }}

# Overrides default cluster SVIP with the one specified. This is
# required or deployments that have implemented the use of VLANs for
# iSCSI networks in their cloud. (string value)
# from $options.sf_svip
{{ if not $options.sf_svip }}#{{ end }}sf_svip = {{ $options.sf_svip | default "<None>" }}

# Create an internal mapping of volume IDs and account.  Optimizes
# lookups and performance at the expense of memory, very large
# deployments may want to consider setting to False. (boolean value)
# from $options.sf_enable_volume_mapping
{{ if not $options.sf_enable_volume_mapping }}#{{ end }}sf_enable_volume_mapping = {{ $options.sf_enable_volume_mapping | default "true" }}

# SolidFire API port. Useful if the device api is behind a proxy on a
# different port. (port value)
# Minimum value: 0
# Maximum value: 65535
# from $options.sf_api_port
{{ if not $options.sf_api_port }}#{{ end }}sf_api_port = {{ $options.sf_api_port | default "443" }}

# Utilize volume access groups on a per-tenant basis. (boolean value)
# from $options.sf_enable_vag
{{ if not $options.sf_enable_vag }}#{{ end }}sf_enable_vag = {{ $options.sf_enable_vag | default "false" }}

# Hostname for the CoprHD Instance (string value)
# from $options.coprhd_hostname
{{ if not $options.coprhd_hostname }}#{{ end }}coprhd_hostname = {{ $options.coprhd_hostname | default "<None>" }}

# Port for the CoprHD Instance (port value)
# Minimum value: 0
# Maximum value: 65535
# from $options.coprhd_port
{{ if not $options.coprhd_port }}#{{ end }}coprhd_port = {{ $options.coprhd_port | default "4443" }}

# Username for accessing the CoprHD Instance (string value)
# from $options.coprhd_username
{{ if not $options.coprhd_username }}#{{ end }}coprhd_username = {{ $options.coprhd_username | default "<None>" }}

# Password for accessing the CoprHD Instance (string value)
# from $options.coprhd_password
{{ if not $options.coprhd_password }}#{{ end }}coprhd_password = {{ $options.coprhd_password | default "<None>" }}

# Tenant to utilize within the CoprHD Instance (string value)
# from $options.coprhd_tenant
{{ if not $options.coprhd_tenant }}#{{ end }}coprhd_tenant = {{ $options.coprhd_tenant | default "<None>" }}

# Project to utilize within the CoprHD Instance (string value)
# from $options.coprhd_project
{{ if not $options.coprhd_project }}#{{ end }}coprhd_project = {{ $options.coprhd_project | default "<None>" }}

# Virtual Array to utilize within the CoprHD Instance (string value)
# from $options.coprhd_varray
{{ if not $options.coprhd_varray }}#{{ end }}coprhd_varray = {{ $options.coprhd_varray | default "<None>" }}

# True | False to indicate if the storage array in CoprHD is VMAX or
# VPLEX (boolean value)
# from $options.coprhd_emulate_snapshot
{{ if not $options.coprhd_emulate_snapshot }}#{{ end }}coprhd_emulate_snapshot = {{ $options.coprhd_emulate_snapshot | default "false" }}

# These values will be used for CloudByte storage's addQos API call.
# (dict value)
# from $options.cb_add_qosgroup
{{ if not $options.cb_add_qosgroup }}#{{ end }}cb_add_qosgroup = {{ $options.cb_add_qosgroup | default "graceallowed:false,iops:10,iopscontrol:true,latency:15,memlimit:0,networkspeed:0,throughput:0,tpcontrol:false" }}

# These values will be used for CloudByte storage's createVolume API
# call. (dict value)
# from $options.cb_create_volume
{{ if not $options.cb_create_volume }}#{{ end }}cb_create_volume = {{ $options.cb_create_volume | default "blocklength:512B,compression:off,deduplication:off,protocoltype:ISCSI,recordsize:16k,sync:always" }}

# Driver will use this API key to authenticate against the CloudByte
# storage's management interface. (string value)
# from $options.cb_apikey
{{ if not $options.cb_apikey }}#{{ end }}cb_apikey = {{ $options.cb_apikey | default "<None>" }}

# CloudByte storage specific account name. This maps to a project name
# in OpenStack. (string value)
# from $options.cb_account_name
{{ if not $options.cb_account_name }}#{{ end }}cb_account_name = {{ $options.cb_account_name | default "<None>" }}

# This corresponds to the name of Tenant Storage Machine (TSM) in
# CloudByte storage. A volume will be created in this TSM. (string
# value)
# from $options.cb_tsm_name
{{ if not $options.cb_tsm_name }}#{{ end }}cb_tsm_name = {{ $options.cb_tsm_name | default "<None>" }}

# A retry value in seconds. Will be used by the driver to check if
# volume creation was successful in CloudByte storage. (integer value)
# from $options.cb_confirm_volume_create_retry_interval
{{ if not $options.cb_confirm_volume_create_retry_interval }}#{{ end }}cb_confirm_volume_create_retry_interval = {{ $options.cb_confirm_volume_create_retry_interval | default "5" }}

# Will confirm a successful volume creation in CloudByte storage by
# making this many number of attempts. (integer value)
# from $options.cb_confirm_volume_create_retries
{{ if not $options.cb_confirm_volume_create_retries }}#{{ end }}cb_confirm_volume_create_retries = {{ $options.cb_confirm_volume_create_retries | default "3" }}

# A retry value in seconds. Will be used by the driver to check if
# volume deletion was successful in CloudByte storage. (integer value)
# from $options.cb_confirm_volume_delete_retry_interval
{{ if not $options.cb_confirm_volume_delete_retry_interval }}#{{ end }}cb_confirm_volume_delete_retry_interval = {{ $options.cb_confirm_volume_delete_retry_interval | default "5" }}

# Will confirm a successful volume deletion in CloudByte storage by
# making this many number of attempts. (integer value)
# from $options.cb_confirm_volume_delete_retries
{{ if not $options.cb_confirm_volume_delete_retries }}#{{ end }}cb_confirm_volume_delete_retries = {{ $options.cb_confirm_volume_delete_retries | default "3" }}

# This corresponds to the discovery authentication group in CloudByte
# storage. Chap users are added to this group. Driver uses the first
# user found for this group. Default value is None. (string value)
# from $options.cb_auth_group
{{ if not $options.cb_auth_group }}#{{ end }}cb_auth_group = {{ $options.cb_auth_group | default "<None>" }}

# These values will be used for CloudByte storage's updateQosGroup API
# call. (list value)
# from $options.cb_update_qos_group
{{ if not $options.cb_update_qos_group }}#{{ end }}cb_update_qos_group = {{ $options.cb_update_qos_group | default "iops,latency,graceallowed" }}

# These values will be used for CloudByte storage's updateFileSystem
# API call. (list value)
# from $options.cb_update_file_system
{{ if not $options.cb_update_file_system }}#{{ end }}cb_update_file_system = {{ $options.cb_update_file_system | default "compression,sync,noofcopies,readonly" }}

# Number of nodes that should replicate the data. (integer value)
# from $options.drbdmanage_redundancy
{{ if not $options.drbdmanage_redundancy }}#{{ end }}drbdmanage_redundancy = {{ $options.drbdmanage_redundancy | default "1" }}

# Resource deployment completion wait policy. (string value)
# from $options.drbdmanage_resource_policy
{{ if not $options.drbdmanage_resource_policy }}#{{ end }}drbdmanage_resource_policy = {{ $options.drbdmanage_resource_policy | default "{\"ratio\": \"0.51\", \"timeout\": \"60\"}" }}

# Disk options to set on new resources. See http://www.drbd.org/en/doc
# /users-guide-90/re-drbdconf for all the details. (string value)
# from $options.drbdmanage_disk_options
{{ if not $options.drbdmanage_disk_options }}#{{ end }}drbdmanage_disk_options = {{ $options.drbdmanage_disk_options | default "{\"c-min-rate\": \"4M\"}" }}

# Net options to set on new resources. See http://www.drbd.org/en/doc
# /users-guide-90/re-drbdconf for all the details. (string value)
# from $options.drbdmanage_net_options
{{ if not $options.drbdmanage_net_options }}#{{ end }}drbdmanage_net_options = {{ $options.drbdmanage_net_options | default "{\"connect-int\": \"4\", \"allow-two-primaries\": \"yes\", \"ko-count\": \"30\", \"max-buffers\": \"20000\", \"ping-timeout\": \"100\"}" }}

# Resource options to set on new resources. See
# http://www.drbd.org/en/doc/users-guide-90/re-drbdconf for all the
# details. (string value)
# from $options.drbdmanage_resource_options
{{ if not $options.drbdmanage_resource_options }}#{{ end }}drbdmanage_resource_options = {{ $options.drbdmanage_resource_options | default "{\"auto-promote-timeout\": \"300\"}" }}

# Snapshot completion wait policy. (string value)
# from $options.drbdmanage_snapshot_policy
{{ if not $options.drbdmanage_snapshot_policy }}#{{ end }}drbdmanage_snapshot_policy = {{ $options.drbdmanage_snapshot_policy | default "{\"count\": \"1\", \"timeout\": \"60\"}" }}

# Volume resize completion wait policy. (string value)
# from $options.drbdmanage_resize_policy
{{ if not $options.drbdmanage_resize_policy }}#{{ end }}drbdmanage_resize_policy = {{ $options.drbdmanage_resize_policy | default "{\"timeout\": \"60\"}" }}

# Resource deployment completion wait plugin. (string value)
# from $options.drbdmanage_resource_plugin
{{ if not $options.drbdmanage_resource_plugin }}#{{ end }}drbdmanage_resource_plugin = {{ $options.drbdmanage_resource_plugin | default "drbdmanage.plugins.plugins.wait_for.WaitForResource" }}

# Snapshot completion wait plugin. (string value)
# from $options.drbdmanage_snapshot_plugin
{{ if not $options.drbdmanage_snapshot_plugin }}#{{ end }}drbdmanage_snapshot_plugin = {{ $options.drbdmanage_snapshot_plugin | default "drbdmanage.plugins.plugins.wait_for.WaitForSnapshot" }}

# Volume resize completion wait plugin. (string value)
# from $options.drbdmanage_resize_plugin
{{ if not $options.drbdmanage_resize_plugin }}#{{ end }}drbdmanage_resize_plugin = {{ $options.drbdmanage_resize_plugin | default "drbdmanage.plugins.plugins.wait_for.WaitForVolumeSize" }}

# If set, the c-vol node will receive a useable
#                 /dev/drbdX device, even if the actual data is stored
# on
#                 other nodes only.
#                 This is useful for debugging, maintenance, and to be
#                 able to do the iSCSI export from the c-vol node.
# (boolean value)
# from $options.drbdmanage_devs_on_controller
{{ if not $options.drbdmanage_devs_on_controller }}#{{ end }}drbdmanage_devs_on_controller = {{ $options.drbdmanage_devs_on_controller | default "true" }}

# Pool or Vdisk name to use for volume creation. (string value)
# from $options.dothill_backend_name
{{ if not $options.dothill_backend_name }}#{{ end }}dothill_backend_name = {{ $options.dothill_backend_name | default "A" }}

# linear (for Vdisk) or virtual (for Pool). (string value)
# Allowed values: linear, virtual
# from $options.dothill_backend_type
{{ if not $options.dothill_backend_type }}#{{ end }}dothill_backend_type = {{ $options.dothill_backend_type | default "virtual" }}

# DotHill API interface protocol. (string value)
# Allowed values: http, https
# from $options.dothill_api_protocol
{{ if not $options.dothill_api_protocol }}#{{ end }}dothill_api_protocol = {{ $options.dothill_api_protocol | default "https" }}

# Whether to verify DotHill array SSL certificate. (boolean value)
# from $options.dothill_verify_certificate
{{ if not $options.dothill_verify_certificate }}#{{ end }}dothill_verify_certificate = {{ $options.dothill_verify_certificate | default "false" }}

# DotHill array SSL certificate path. (string value)
# from $options.dothill_verify_certificate_path
{{ if not $options.dothill_verify_certificate_path }}#{{ end }}dothill_verify_certificate_path = {{ $options.dothill_verify_certificate_path | default "<None>" }}

# List of comma-separated target iSCSI IP addresses. (list value)
# from $options.dothill_iscsi_ips
{{ if not $options.dothill_iscsi_ips }}#{{ end }}dothill_iscsi_ips = {{ $options.dothill_iscsi_ips | default "" }}

# File with the list of available gluster shares (string value)
# from $options.glusterfs_shares_config
{{ if not $options.glusterfs_shares_config }}#{{ end }}glusterfs_shares_config = {{ $options.glusterfs_shares_config | default "/etc/cinder/glusterfs_shares" }}

# Base dir containing mount points for gluster shares. (string value)
# from $options.glusterfs_mount_point_base
{{ if not $options.glusterfs_mount_point_base }}#{{ end }}glusterfs_mount_point_base = {{ $options.glusterfs_mount_point_base | default "$state_path/mnt" }}

# REST API authorization token. (string value)
# from $options.pure_api_token
{{ if not $options.pure_api_token }}#{{ end }}pure_api_token = {{ $options.pure_api_token | default "<None>" }}

# Automatically determine an oversubscription ratio based on the
# current total data reduction values. If used this calculated value
# will override the max_over_subscription_ratio config option.
# (boolean value)
# from $options.pure_automatic_max_oversubscription_ratio
{{ if not $options.pure_automatic_max_oversubscription_ratio }}#{{ end }}pure_automatic_max_oversubscription_ratio = {{ $options.pure_automatic_max_oversubscription_ratio | default "true" }}

# Snapshot replication interval in seconds. (integer value)
# from $options.pure_replica_interval_default
{{ if not $options.pure_replica_interval_default }}#{{ end }}pure_replica_interval_default = {{ $options.pure_replica_interval_default | default "900" }}

# Retain all snapshots on target for this time (in seconds.) (integer
# value)
# from $options.pure_replica_retention_short_term_default
{{ if not $options.pure_replica_retention_short_term_default }}#{{ end }}pure_replica_retention_short_term_default = {{ $options.pure_replica_retention_short_term_default | default "14400" }}

# Retain how many snapshots for each day. (integer value)
# from $options.pure_replica_retention_long_term_per_day_default
{{ if not $options.pure_replica_retention_long_term_per_day_default }}#{{ end }}pure_replica_retention_long_term_per_day_default = {{ $options.pure_replica_retention_long_term_per_day_default | default "3" }}

# Retain snapshots per day on target for this time (in days.) (integer
# value)
# from $options.pure_replica_retention_long_term_default
{{ if not $options.pure_replica_retention_long_term_default }}#{{ end }}pure_replica_retention_long_term_default = {{ $options.pure_replica_retention_long_term_default | default "7" }}

# When enabled, all Pure volumes, snapshots, and protection groups
# will be eradicated at the time of deletion in Cinder. Data will NOT
# be recoverable after a delete with this set to True! When disabled,
# volumes and snapshots will go into pending eradication state and can
# be recovered. (boolean value)
# from $options.pure_eradicate_on_delete
{{ if not $options.pure_eradicate_on_delete }}#{{ end }}pure_eradicate_on_delete = {{ $options.pure_eradicate_on_delete | default "false" }}

# Proxy driver that connects to the IBM Storage Array (string value)
# from $options.proxy
{{ if not $options.proxy }}#{{ end }}proxy = {{ $options.proxy | default "storage.proxy.IBMStorageProxy" }}

# Connection type to the IBM Storage Array (string value)
# Allowed values: fibre_channel, iscsi
# from $options.connection_type
{{ if not $options.connection_type }}#{{ end }}connection_type = {{ $options.connection_type | default "iscsi" }}

# CHAP authentication mode, effective only for iscsi
# (disabled|enabled) (string value)
# Allowed values: disabled, enabled
# from $options.chap
{{ if not $options.chap }}#{{ end }}chap = {{ $options.chap | default "disabled" }}

# List of Management IP addresses (separated by commas) (string value)
# from $options.management_ips
{{ if not $options.management_ips }}#{{ end }}management_ips = {{ $options.management_ips | default "" }}

# IP address for connecting to VMware vCenter server. (string value)
# from $options.vmware_host_ip
{{ if not $options.vmware_host_ip }}#{{ end }}vmware_host_ip = {{ $options.vmware_host_ip | default "<None>" }}

# Port number for connecting to VMware vCenter server. (port value)
# Minimum value: 0
# Maximum value: 65535
# from $options.vmware_host_port
{{ if not $options.vmware_host_port }}#{{ end }}vmware_host_port = {{ $options.vmware_host_port | default "443" }}

# Username for authenticating with VMware vCenter server. (string
# value)
# from $options.vmware_host_username
{{ if not $options.vmware_host_username }}#{{ end }}vmware_host_username = {{ $options.vmware_host_username | default "<None>" }}

# Password for authenticating with VMware vCenter server. (string
# value)
# from $options.vmware_host_password
{{ if not $options.vmware_host_password }}#{{ end }}vmware_host_password = {{ $options.vmware_host_password | default "<None>" }}

# Optional VIM service WSDL Location e.g
# http://<server>/vimService.wsdl. Optional over-ride to default
# location for bug work-arounds. (string value)
# from $options.vmware_wsdl_location
{{ if not $options.vmware_wsdl_location }}#{{ end }}vmware_wsdl_location = {{ $options.vmware_wsdl_location | default "<None>" }}

# Number of times VMware vCenter server API must be retried upon
# connection related issues. (integer value)
# from $options.vmware_api_retry_count
{{ if not $options.vmware_api_retry_count }}#{{ end }}vmware_api_retry_count = {{ $options.vmware_api_retry_count | default "10" }}

# The interval (in seconds) for polling remote tasks invoked on VMware
# vCenter server. (floating point value)
# from $options.vmware_task_poll_interval
{{ if not $options.vmware_task_poll_interval }}#{{ end }}vmware_task_poll_interval = {{ $options.vmware_task_poll_interval | default "2.0" }}

# Name of the vCenter inventory folder that will contain Cinder
# volumes. This folder will be created under
# "OpenStack/<project_folder>", where project_folder is of format
# "Project (<volume_project_id>)". (string value)
# from $options.vmware_volume_folder
{{ if not $options.vmware_volume_folder }}#{{ end }}vmware_volume_folder = {{ $options.vmware_volume_folder | default "Volumes" }}

# Timeout in seconds for VMDK volume transfer between Cinder and
# Glance. (integer value)
# from $options.vmware_image_transfer_timeout_secs
{{ if not $options.vmware_image_transfer_timeout_secs }}#{{ end }}vmware_image_transfer_timeout_secs = {{ $options.vmware_image_transfer_timeout_secs | default "7200" }}

# Max number of objects to be retrieved per batch. Query results will
# be obtained in batches from the server and not in one shot. Server
# may still limit the count to something less than the configured
# value. (integer value)
# from $options.vmware_max_objects_retrieval
{{ if not $options.vmware_max_objects_retrieval }}#{{ end }}vmware_max_objects_retrieval = {{ $options.vmware_max_objects_retrieval | default "100" }}

# Optional string specifying the VMware vCenter server version. The
# driver attempts to retrieve the version from VMware vCenter server.
# Set this configuration only if you want to override the vCenter
# server version. (string value)
# from $options.vmware_host_version
{{ if not $options.vmware_host_version }}#{{ end }}vmware_host_version = {{ $options.vmware_host_version | default "<None>" }}

# Directory where virtual disks are stored during volume backup and
# restore. (string value)
# from $options.vmware_tmp_dir
{{ if not $options.vmware_tmp_dir }}#{{ end }}vmware_tmp_dir = {{ $options.vmware_tmp_dir | default "/tmp" }}

# CA bundle file to use in verifying the vCenter server certificate.
# (string value)
# from $options.vmware_ca_file
{{ if not $options.vmware_ca_file }}#{{ end }}vmware_ca_file = {{ $options.vmware_ca_file | default "<None>" }}

# If true, the vCenter server certificate is not verified. If false,
# then the default CA truststore is used for verification. This option
# is ignored if "vmware_ca_file" is set. (boolean value)
# from $options.vmware_insecure
{{ if not $options.vmware_insecure }}#{{ end }}vmware_insecure = {{ $options.vmware_insecure | default "false" }}

# Name of a vCenter compute cluster where volumes should be created.
# (multi valued)
# from $options.vmware_cluster_name (multiopt)
{{ if not $options.vmware_cluster_name }}#vmware_cluster_name = {{ $options.vmware_cluster_name | default "" }}{{ else }}{{ range $options.vmware_cluster_name }}vmware_cluster_name = {{ . }}{{ end }}{{ end }}

# Pool or Vdisk name to use for volume creation. (string value)
# from $options.lenovo_backend_name
{{ if not $options.lenovo_backend_name }}#{{ end }}lenovo_backend_name = {{ $options.lenovo_backend_name | default "A" }}

# linear (for VDisk) or virtual (for Pool). (string value)
# Allowed values: linear, virtual
# from $options.lenovo_backend_type
{{ if not $options.lenovo_backend_type }}#{{ end }}lenovo_backend_type = {{ $options.lenovo_backend_type | default "virtual" }}

# Lenovo api interface protocol. (string value)
# Allowed values: http, https
# from $options.lenovo_api_protocol
{{ if not $options.lenovo_api_protocol }}#{{ end }}lenovo_api_protocol = {{ $options.lenovo_api_protocol | default "https" }}

# Whether to verify Lenovo array SSL certificate. (boolean value)
# from $options.lenovo_verify_certificate
{{ if not $options.lenovo_verify_certificate }}#{{ end }}lenovo_verify_certificate = {{ $options.lenovo_verify_certificate | default "false" }}

# Lenovo array SSL certificate path. (string value)
# from $options.lenovo_verify_certificate_path
{{ if not $options.lenovo_verify_certificate_path }}#{{ end }}lenovo_verify_certificate_path = {{ $options.lenovo_verify_certificate_path | default "<None>" }}

# List of comma-separated target iSCSI IP addresses. (list value)
# from $options.lenovo_iscsi_ips
{{ if not $options.lenovo_iscsi_ips }}#{{ end }}lenovo_iscsi_ips = {{ $options.lenovo_iscsi_ips | default "" }}

# REST server port. (string value)
# from $options.sio_rest_server_port
{{ if not $options.sio_rest_server_port }}#{{ end }}sio_rest_server_port = {{ $options.sio_rest_server_port | default "443" }}

# Verify server certificate. (boolean value)
# from $options.sio_verify_server_certificate
{{ if not $options.sio_verify_server_certificate }}#{{ end }}sio_verify_server_certificate = {{ $options.sio_verify_server_certificate | default "false" }}

# Server certificate path. (string value)
# from $options.sio_server_certificate_path
{{ if not $options.sio_server_certificate_path }}#{{ end }}sio_server_certificate_path = {{ $options.sio_server_certificate_path | default "<None>" }}

# Round up volume capacity. (boolean value)
# from $options.sio_round_volume_capacity
{{ if not $options.sio_round_volume_capacity }}#{{ end }}sio_round_volume_capacity = {{ $options.sio_round_volume_capacity | default "true" }}

# Unmap volume before deletion. (boolean value)
# from $options.sio_unmap_volume_before_deletion
{{ if not $options.sio_unmap_volume_before_deletion }}#{{ end }}sio_unmap_volume_before_deletion = {{ $options.sio_unmap_volume_before_deletion | default "false" }}

# Protection Domain ID. (string value)
# from $options.sio_protection_domain_id
{{ if not $options.sio_protection_domain_id }}#{{ end }}sio_protection_domain_id = {{ $options.sio_protection_domain_id | default "<None>" }}

# Protection Domain name. (string value)
# from $options.sio_protection_domain_name
{{ if not $options.sio_protection_domain_name }}#{{ end }}sio_protection_domain_name = {{ $options.sio_protection_domain_name | default "<None>" }}

# Storage Pools. (string value)
# from $options.sio_storage_pools
{{ if not $options.sio_storage_pools }}#{{ end }}sio_storage_pools = {{ $options.sio_storage_pools | default "<None>" }}

# Storage Pool name. (string value)
# from $options.sio_storage_pool_name
{{ if not $options.sio_storage_pool_name }}#{{ end }}sio_storage_pool_name = {{ $options.sio_storage_pool_name | default "<None>" }}

# Storage Pool ID. (string value)
# from $options.sio_storage_pool_id
{{ if not $options.sio_storage_pool_id }}#{{ end }}sio_storage_pool_id = {{ $options.sio_storage_pool_id | default "<None>" }}

# max_over_subscription_ratio setting for the ScaleIO driver. This
# replaces the general max_over_subscription_ratio which has no effect
# in this driver.Maximum value allowed for ScaleIO is 10.0. (floating
# point value)
# from $options.sio_max_over_subscription_ratio
{{ if not $options.sio_max_over_subscription_ratio }}#{{ end }}sio_max_over_subscription_ratio = {{ $options.sio_max_over_subscription_ratio | default "10.0" }}

# Group name to use for creating volumes. Defaults to "group-0".
# (string value)
# from $options.eqlx_group_name
{{ if not $options.eqlx_group_name }}#{{ end }}eqlx_group_name = {{ $options.eqlx_group_name | default "group-0" }}

# Timeout for the Group Manager cli command execution. Default is 30.
# Note that this option is deprecated in favour of "ssh_conn_timeout"
# as specified in cinder/volume/drivers/san/san.py and will be removed
# in M release. (integer value)
# from $options.eqlx_cli_timeout
{{ if not $options.eqlx_cli_timeout }}#{{ end }}eqlx_cli_timeout = {{ $options.eqlx_cli_timeout | default "30" }}

# Maximum retry count for reconnection. Default is 5. (integer value)
# Minimum value: 0
# from $options.eqlx_cli_max_retries
{{ if not $options.eqlx_cli_max_retries }}#{{ end }}eqlx_cli_max_retries = {{ $options.eqlx_cli_max_retries | default "5" }}

# Use CHAP authentication for targets. Note that this option is
# deprecated in favour of "use_chap_auth" as specified in
# cinder/volume/driver.py and will be removed in next release.
# (boolean value)
# from $options.eqlx_use_chap
{{ if not $options.eqlx_use_chap }}#{{ end }}eqlx_use_chap = {{ $options.eqlx_use_chap | default "false" }}

# Existing CHAP account name. Note that this option is deprecated in
# favour of "chap_username" as specified in cinder/volume/driver.py
# and will be removed in next release. (string value)
# from $options.eqlx_chap_login
{{ if not $options.eqlx_chap_login }}#{{ end }}eqlx_chap_login = {{ $options.eqlx_chap_login | default "admin" }}

# Password for specified CHAP account name. Note that this option is
# deprecated in favour of "chap_password" as specified in
# cinder/volume/driver.py and will be removed in the next release
# (string value)
# from $options.eqlx_chap_password
{{ if not $options.eqlx_chap_password }}#{{ end }}eqlx_chap_password = {{ $options.eqlx_chap_password | default "password" }}

# Pool in which volumes will be created. Defaults to "default".
# (string value)
# from $options.eqlx_pool
{{ if not $options.eqlx_pool }}#{{ end }}eqlx_pool = {{ $options.eqlx_pool | default "default" }}

# RPC port to connect to Coho Data MicroArray (integer value)
# from $options.coho_rpc_port
{{ if not $options.coho_rpc_port }}#{{ end }}coho_rpc_port = {{ $options.coho_rpc_port | default "2049" }}

# Path or URL to Scality SOFS configuration file (string value)
# from $options.scality_sofs_config
{{ if not $options.scality_sofs_config }}#{{ end }}scality_sofs_config = {{ $options.scality_sofs_config | default "<None>" }}

# Base dir where Scality SOFS shall be mounted (string value)
# from $options.scality_sofs_mount_point
{{ if not $options.scality_sofs_mount_point }}#{{ end }}scality_sofs_mount_point = {{ $options.scality_sofs_mount_point | default "$state_path/scality" }}

# Path from Scality SOFS root to volume dir (string value)
# from $options.scality_sofs_volume_dir
{{ if not $options.scality_sofs_volume_dir }}#{{ end }}scality_sofs_volume_dir = {{ $options.scality_sofs_volume_dir | default "cinder/volumes" }}

# Default storage pool for volumes. (integer value)
# from $options.ise_storage_pool
{{ if not $options.ise_storage_pool }}#{{ end }}ise_storage_pool = {{ $options.ise_storage_pool | default "1" }}

# Raid level for ISE volumes. (integer value)
# from $options.ise_raid
{{ if not $options.ise_raid }}#{{ end }}ise_raid = {{ $options.ise_raid | default "1" }}

# Number of retries (per port) when establishing connection to ISE
# management port. (integer value)
# from $options.ise_connection_retries
{{ if not $options.ise_connection_retries }}#{{ end }}ise_connection_retries = {{ $options.ise_connection_retries | default "5" }}

# Interval (secs) between retries. (integer value)
# from $options.ise_retry_interval
{{ if not $options.ise_retry_interval }}#{{ end }}ise_retry_interval = {{ $options.ise_retry_interval | default "1" }}

# Number on retries to get completion status after issuing a command
# to ISE. (integer value)
# from $options.ise_completion_retries
{{ if not $options.ise_completion_retries }}#{{ end }}ise_completion_retries = {{ $options.ise_completion_retries | default "30" }}

# Connect with multipath (FC only; iSCSI multipath is controlled by
# Nova) (boolean value)
# from $options.storwize_svc_multipath_enabled
{{ if not $options.storwize_svc_multipath_enabled }}#{{ end }}storwize_svc_multipath_enabled = {{ $options.storwize_svc_multipath_enabled | default "false" }}

# FSS pool id in which FalconStor volumes are stored. (integer value)
# from $options.fss_pool
{{ if not $options.fss_pool }}#{{ end }}fss_pool = {{ $options.fss_pool | default "" }}

# Enable HTTP debugging to FSS (boolean value)
# from $options.fss_debug
{{ if not $options.fss_debug }}#{{ end }}fss_debug = {{ $options.fss_debug | default "false" }}

# FSS additional retry list, separate by ; (string value)
# from $options.additional_retry_list
{{ if not $options.additional_retry_list }}#{{ end }}additional_retry_list = {{ $options.additional_retry_list | default "" }}

# Storage pool name. (string value)
# from $options.zfssa_pool
{{ if not $options.zfssa_pool }}#{{ end }}zfssa_pool = {{ $options.zfssa_pool | default "<None>" }}

# Project name. (string value)
# from $options.zfssa_project
{{ if not $options.zfssa_project }}#{{ end }}zfssa_project = {{ $options.zfssa_project | default "<None>" }}

# Block size. (string value)
# Allowed values: 512, 1k, 2k, 4k, 8k, 16k, 32k, 64k, 128k
# from $options.zfssa_lun_volblocksize
{{ if not $options.zfssa_lun_volblocksize }}#{{ end }}zfssa_lun_volblocksize = {{ $options.zfssa_lun_volblocksize | default "8k" }}

# Flag to enable sparse (thin-provisioned): True, False. (boolean
# value)
# from $options.zfssa_lun_sparse
{{ if not $options.zfssa_lun_sparse }}#{{ end }}zfssa_lun_sparse = {{ $options.zfssa_lun_sparse | default "false" }}

# Data compression. (string value)
# Allowed values: off, lzjb, gzip-2, gzip, gzip-9
# from $options.zfssa_lun_compression
{{ if not $options.zfssa_lun_compression }}#{{ end }}zfssa_lun_compression = {{ $options.zfssa_lun_compression | default "off" }}

# Synchronous write bias. (string value)
# Allowed values: latency, throughput
# from $options.zfssa_lun_logbias
{{ if not $options.zfssa_lun_logbias }}#{{ end }}zfssa_lun_logbias = {{ $options.zfssa_lun_logbias | default "latency" }}

# iSCSI initiator group. (string value)
# from $options.zfssa_initiator_group
{{ if not $options.zfssa_initiator_group }}#{{ end }}zfssa_initiator_group = {{ $options.zfssa_initiator_group | default "" }}

# iSCSI initiator IQNs. (comma separated) (string value)
# from $options.zfssa_initiator
{{ if not $options.zfssa_initiator }}#{{ end }}zfssa_initiator = {{ $options.zfssa_initiator | default "" }}

# iSCSI initiator CHAP user (name). (string value)
# from $options.zfssa_initiator_user
{{ if not $options.zfssa_initiator_user }}#{{ end }}zfssa_initiator_user = {{ $options.zfssa_initiator_user | default "" }}

# Secret of the iSCSI initiator CHAP user. (string value)
# from $options.zfssa_initiator_password
{{ if not $options.zfssa_initiator_password }}#{{ end }}zfssa_initiator_password = {{ $options.zfssa_initiator_password | default "" }}

# iSCSI initiators configuration. (string value)
# from $options.zfssa_initiator_config
{{ if not $options.zfssa_initiator_config }}#{{ end }}zfssa_initiator_config = {{ $options.zfssa_initiator_config | default "" }}

# iSCSI target group name. (string value)
# from $options.zfssa_target_group
{{ if not $options.zfssa_target_group }}#{{ end }}zfssa_target_group = {{ $options.zfssa_target_group | default "tgt-grp" }}

# iSCSI target CHAP user (name). (string value)
# from $options.zfssa_target_user
{{ if not $options.zfssa_target_user }}#{{ end }}zfssa_target_user = {{ $options.zfssa_target_user | default "" }}

# Secret of the iSCSI target CHAP user. (string value)
# from $options.zfssa_target_password
{{ if not $options.zfssa_target_password }}#{{ end }}zfssa_target_password = {{ $options.zfssa_target_password | default "" }}

# iSCSI target portal (Data-IP:Port, w.x.y.z:3260). (string value)
# from $options.zfssa_target_portal
{{ if not $options.zfssa_target_portal }}#{{ end }}zfssa_target_portal = {{ $options.zfssa_target_portal | default "<None>" }}

# Network interfaces of iSCSI targets. (comma separated) (string
# value)
# from $options.zfssa_target_interfaces
{{ if not $options.zfssa_target_interfaces }}#{{ end }}zfssa_target_interfaces = {{ $options.zfssa_target_interfaces | default "<None>" }}

# REST connection timeout. (seconds) (integer value)
# from $options.zfssa_rest_timeout
{{ if not $options.zfssa_rest_timeout }}#{{ end }}zfssa_rest_timeout = {{ $options.zfssa_rest_timeout | default "<None>" }}

# IP address used for replication data. (maybe the same as data ip)
# (string value)
# from $options.zfssa_replication_ip
{{ if not $options.zfssa_replication_ip }}#{{ end }}zfssa_replication_ip = {{ $options.zfssa_replication_ip | default "" }}

# Flag to enable local caching: True, False. (boolean value)
# from $options.zfssa_enable_local_cache
{{ if not $options.zfssa_enable_local_cache }}#{{ end }}zfssa_enable_local_cache = {{ $options.zfssa_enable_local_cache | default "true" }}

# Name of ZFSSA project where cache volumes are stored. (string value)
# from $options.zfssa_cache_project
{{ if not $options.zfssa_cache_project }}#{{ end }}zfssa_cache_project = {{ $options.zfssa_cache_project | default "os-cinder-cache" }}

# Driver policy for volume manage. (string value)
# Allowed values: loose, strict
# from $options.zfssa_manage_policy
{{ if not $options.zfssa_manage_policy }}#{{ end }}zfssa_manage_policy = {{ $options.zfssa_manage_policy | default "loose" }}

# Nimble Controller pool name (string value)
# from $options.nimble_pool_name
{{ if not $options.nimble_pool_name }}#{{ end }}nimble_pool_name = {{ $options.nimble_pool_name | default "default" }}

# Nimble Subnet Label (string value)
# from $options.nimble_subnet_label
{{ if not $options.nimble_subnet_label }}#{{ end }}nimble_subnet_label = {{ $options.nimble_subnet_label | default "*" }}

# Path to store VHD backed volumes (string value)
# from $options.windows_iscsi_lun_path
{{ if not $options.windows_iscsi_lun_path }}#{{ end }}windows_iscsi_lun_path = {{ $options.windows_iscsi_lun_path | default "C:\\iSCSIVirtualDisks" }}

# VNX authentication scope type. By default, the value is global.
# (string value)
# from $options.storage_vnx_authentication_type
{{ if not $options.storage_vnx_authentication_type }}#{{ end }}storage_vnx_authentication_type = {{ $options.storage_vnx_authentication_type | default "global" }}

# Directory path that contains the VNX security file. Make sure the
# security file is generated first. (string value)
# from $options.storage_vnx_security_file_dir
{{ if not $options.storage_vnx_security_file_dir }}#{{ end }}storage_vnx_security_file_dir = {{ $options.storage_vnx_security_file_dir | default "<None>" }}

# Naviseccli Path. (string value)
# from $options.naviseccli_path
{{ if not $options.naviseccli_path }}#{{ end }}naviseccli_path = {{ $options.naviseccli_path | default "<None>" }}

# Comma-separated list of storage pool names to be used. (list value)
# from $options.storage_vnx_pool_names
{{ if not $options.storage_vnx_pool_names }}#{{ end }}storage_vnx_pool_names = {{ $options.storage_vnx_pool_names | default "<None>" }}

# Default timeout for CLI operations in minutes. For example, LUN
# migration is a typical long running operation, which depends on the
# LUN size and the load of the array. An upper bound in the specific
# deployment can be set to avoid unnecessary long wait. By default, it
# is 365 days long. (integer value)
# from $options.default_timeout
{{ if not $options.default_timeout }}#{{ end }}default_timeout = {{ $options.default_timeout | default "31536000" }}

# Default max number of LUNs in a storage group. By default, the value
# is 255. (integer value)
# from $options.max_luns_per_storage_group
{{ if not $options.max_luns_per_storage_group }}#{{ end }}max_luns_per_storage_group = {{ $options.max_luns_per_storage_group | default "255" }}

# To destroy storage group when the last LUN is removed from it. By
# default, the value is False. (boolean value)
# from $options.destroy_empty_storage_group
{{ if not $options.destroy_empty_storage_group }}#{{ end }}destroy_empty_storage_group = {{ $options.destroy_empty_storage_group | default "false" }}

# Mapping between hostname and its iSCSI initiator IP addresses.
# (string value)
# from $options.iscsi_initiators
{{ if not $options.iscsi_initiators }}#{{ end }}iscsi_initiators = {{ $options.iscsi_initiators | default "<None>" }}

# Comma separated iSCSI or FC ports to be used in Nova or Cinder.
# (list value)
# from $options.io_port_list
{{ if not $options.io_port_list }}#{{ end }}io_port_list = {{ $options.io_port_list | default "<None>" }}

# Automatically register initiators. By default, the value is False.
# (boolean value)
# from $options.initiator_auto_registration
{{ if not $options.initiator_auto_registration }}#{{ end }}initiator_auto_registration = {{ $options.initiator_auto_registration | default "false" }}

# Automatically deregister initiators after the related storage group
# is destroyed. By default, the value is False. (boolean value)
# from $options.initiator_auto_deregistration
{{ if not $options.initiator_auto_deregistration }}#{{ end }}initiator_auto_deregistration = {{ $options.initiator_auto_deregistration | default "false" }}

# Report free_capacity_gb as 0 when the limit to maximum number of
# pool LUNs is reached. By default, the value is False. (boolean
# value)
# from $options.check_max_pool_luns_threshold
{{ if not $options.check_max_pool_luns_threshold }}#{{ end }}check_max_pool_luns_threshold = {{ $options.check_max_pool_luns_threshold | default "false" }}

# Delete a LUN even if it is in Storage Groups. By default, the value
# is False. (boolean value)
# from $options.force_delete_lun_in_storagegroup
{{ if not $options.force_delete_lun_in_storagegroup }}#{{ end }}force_delete_lun_in_storagegroup = {{ $options.force_delete_lun_in_storagegroup | default "false" }}

# Force LUN creation even if the full threshold of pool is reached. By
# default, the value is False. (boolean value)
# from $options.ignore_pool_full_threshold
{{ if not $options.ignore_pool_full_threshold }}#{{ end }}ignore_pool_full_threshold = {{ $options.ignore_pool_full_threshold | default "false" }}

# Pool or Vdisk name to use for volume creation. (string value)
# from $options.hpmsa_backend_name
{{ if not $options.hpmsa_backend_name }}#{{ end }}hpmsa_backend_name = {{ $options.hpmsa_backend_name | default "A" }}

# linear (for Vdisk) or virtual (for Pool). (string value)
# Allowed values: linear, virtual
# from $options.hpmsa_backend_type
{{ if not $options.hpmsa_backend_type }}#{{ end }}hpmsa_backend_type = {{ $options.hpmsa_backend_type | default "virtual" }}

# HPMSA API interface protocol. (string value)
# Allowed values: http, https
# from $options.hpmsa_api_protocol
{{ if not $options.hpmsa_api_protocol }}#{{ end }}hpmsa_api_protocol = {{ $options.hpmsa_api_protocol | default "https" }}

# Whether to verify HPMSA array SSL certificate. (boolean value)
# from $options.hpmsa_verify_certificate
{{ if not $options.hpmsa_verify_certificate }}#{{ end }}hpmsa_verify_certificate = {{ $options.hpmsa_verify_certificate | default "false" }}

# HPMSA array SSL certificate path. (string value)
# from $options.hpmsa_verify_certificate_path
{{ if not $options.hpmsa_verify_certificate_path }}#{{ end }}hpmsa_verify_certificate_path = {{ $options.hpmsa_verify_certificate_path | default "<None>" }}

# List of comma-separated target iSCSI IP addresses. (list value)
# from $options.hpmsa_iscsi_ips
{{ if not $options.hpmsa_iscsi_ips }}#{{ end }}hpmsa_iscsi_ips = {{ $options.hpmsa_iscsi_ips | default "" }}

# HPE LeftHand WSAPI Server Url like https://<LeftHand ip>:8081/lhos
# (string value)
# Deprecated group/name - [BACKEND]/hplefthand_api_url
# from $options.hpelefthand_api_url
{{ if not $options.hpelefthand_api_url }}#{{ end }}hpelefthand_api_url = {{ $options.hpelefthand_api_url | default "<None>" }}

# HPE LeftHand Super user username (string value)
# Deprecated group/name - [BACKEND]/hplefthand_username
# from $options.hpelefthand_username
{{ if not $options.hpelefthand_username }}#{{ end }}hpelefthand_username = {{ $options.hpelefthand_username | default "<None>" }}

# HPE LeftHand Super user password (string value)
# Deprecated group/name - [BACKEND]/hplefthand_password
# from $options.hpelefthand_password
{{ if not $options.hpelefthand_password }}#{{ end }}hpelefthand_password = {{ $options.hpelefthand_password | default "<None>" }}

# HPE LeftHand cluster name (string value)
# Deprecated group/name - [BACKEND]/hplefthand_clustername
# from $options.hpelefthand_clustername
{{ if not $options.hpelefthand_clustername }}#{{ end }}hpelefthand_clustername = {{ $options.hpelefthand_clustername | default "<None>" }}

# Configure CHAP authentication for iSCSI connections (Default:
# Disabled) (boolean value)
# Deprecated group/name - [BACKEND]/hplefthand_iscsi_chap_enabled
# from $options.hpelefthand_iscsi_chap_enabled
{{ if not $options.hpelefthand_iscsi_chap_enabled }}#{{ end }}hpelefthand_iscsi_chap_enabled = {{ $options.hpelefthand_iscsi_chap_enabled | default "false" }}

# Enable HTTP debugging to LeftHand (boolean value)
# Deprecated group/name - [BACKEND]/hplefthand_debug
# from $options.hpelefthand_debug
{{ if not $options.hpelefthand_debug }}#{{ end }}hpelefthand_debug = {{ $options.hpelefthand_debug | default "false" }}

# Port number of SSH service. (port value)
# Minimum value: 0
# Maximum value: 65535
# from $options.hpelefthand_ssh_port
{{ if not $options.hpelefthand_ssh_port }}#{{ end }}hpelefthand_ssh_port = {{ $options.hpelefthand_ssh_port | default "16022" }}

# Name for the VG that will contain exported volumes (string value)
# from $options.volume_group
{{ if not $options.volume_group }}#{{ end }}volume_group = {{ $options.volume_group | default "cinder-volumes" }}

# If >0, create LVs with multiple mirrors. Note that this requires
# lvm_mirrors + 2 PVs with available space (integer value)
# from $options.lvm_mirrors
{{ if not $options.lvm_mirrors }}#{{ end }}lvm_mirrors = {{ $options.lvm_mirrors | default "0" }}

# Type of LVM volumes to deploy; (default, thin, or auto). Auto
# defaults to thin if thin is supported. (string value)
# Allowed values: default, thin, auto
# from $options.lvm_type
{{ if not $options.lvm_type }}#{{ end }}lvm_type = {{ $options.lvm_type | default "default" }}

# LVM conf file to use for the LVM driver in Cinder; this setting is
# ignored if the specified file does not exist (You can also specify
# 'None' to not use a conf file even if one exists). (string value)
# from $options.lvm_conf_file
{{ if not $options.lvm_conf_file }}#{{ end }}lvm_conf_file = {{ $options.lvm_conf_file | default "/etc/cinder/lvm.conf" }}

# max_over_subscription_ratio setting for the LVM driver.  If set,
# this takes precedence over the general max_over_subscription_ratio
# option.  If None, the general option is used. (floating point value)
# from $options.lvm_max_over_subscription_ratio
{{ if not $options.lvm_max_over_subscription_ratio }}#{{ end }}lvm_max_over_subscription_ratio = {{ $options.lvm_max_over_subscription_ratio | default "1.0" }}

# Suppress leaked file descriptor warnings in LVM commands. (boolean
# value)
# from $options.lvm_suppress_fd_warnings
{{ if not $options.lvm_suppress_fd_warnings }}#{{ end }}lvm_suppress_fd_warnings = {{ $options.lvm_suppress_fd_warnings | default "false" }}

# Use this file for cinder emc plugin config data (string value)
# from $options.cinder_emc_config_file
{{ if not $options.cinder_emc_config_file }}#{{ end }}cinder_emc_config_file = {{ $options.cinder_emc_config_file | default "/etc/cinder/cinder_emc_config.xml" }}

# Use this value to enable the initiator_check (string value)
# from $options.initiator_check
{{ if not $options.initiator_check }}#{{ end }}initiator_check = {{ $options.initiator_check | default "False" }}

# IP address or Hostname of NAS system. (string value)
# Deprecated group/name - [BACKEND]/nas_ip
# from $options.nas_host
{{ if not $options.nas_host }}#{{ end }}nas_host = {{ $options.nas_host | default "" }}

# User name to connect to NAS system. (string value)
# from $options.nas_login
{{ if not $options.nas_login }}#{{ end }}nas_login = {{ $options.nas_login | default "admin" }}

# Password to connect to NAS system. (string value)
# from $options.nas_password
{{ if not $options.nas_password }}#{{ end }}nas_password = {{ $options.nas_password | default "" }}

# SSH port to use to connect to NAS system. (port value)
# Minimum value: 0
# Maximum value: 65535
# from $options.nas_ssh_port
{{ if not $options.nas_ssh_port }}#{{ end }}nas_ssh_port = {{ $options.nas_ssh_port | default "22" }}

# Filename of private key to use for SSH authentication. (string
# value)
# from $options.nas_private_key
{{ if not $options.nas_private_key }}#{{ end }}nas_private_key = {{ $options.nas_private_key | default "" }}

# Allow network-attached storage systems to operate in a secure
# environment where root level access is not permitted. If set to
# False, access is as the root user and insecure. If set to True,
# access is not as root. If set to auto, a check is done to determine
# if this is a new installation: True is used if so, otherwise False.
# Default is auto. (string value)
# from $options.nas_secure_file_operations
{{ if not $options.nas_secure_file_operations }}#{{ end }}nas_secure_file_operations = {{ $options.nas_secure_file_operations | default "auto" }}

# Set more secure file permissions on network-attached storage volume
# files to restrict broad other/world access. If set to False, volumes
# are created with open permissions. If set to True, volumes are
# created with permissions for the cinder user and group (660). If set
# to auto, a check is done to determine if this is a new installation:
# True is used if so, otherwise False. Default is auto. (string value)
# from $options.nas_secure_file_permissions
{{ if not $options.nas_secure_file_permissions }}#{{ end }}nas_secure_file_permissions = {{ $options.nas_secure_file_permissions | default "auto" }}

# Path to the share to use for storing Cinder volumes. For example:
# "/srv/export1" for an NFS server export available at
# 10.0.5.10:/srv/export1 . (string value)
# from $options.nas_share_path
{{ if not $options.nas_share_path }}#{{ end }}nas_share_path = {{ $options.nas_share_path | default "" }}

# Options used to mount the storage backend file system where Cinder
# volumes are stored. (string value)
# from $options.nas_mount_options
{{ if not $options.nas_mount_options }}#{{ end }}nas_mount_options = {{ $options.nas_mount_options | default "<None>" }}

# Provisioning type that will be used when creating volumes. (string
# value)
# Allowed values: thin, thick
# Deprecated group/name - [BACKEND]/glusterfs_sparsed_volumes
# Deprecated group/name - [BACKEND]/glusterfs_qcow2_volumes
# from $options.nas_volume_prov_type
{{ if not $options.nas_volume_prov_type }}#{{ end }}nas_volume_prov_type = {{ $options.nas_volume_prov_type | default "thin" }}

# XMS cluster id in multi-cluster environment (string value)
# from $options.xtremio_cluster_name
{{ if not $options.xtremio_cluster_name }}#{{ end }}xtremio_cluster_name = {{ $options.xtremio_cluster_name | default "" }}

# Number of retries in case array is busy (integer value)
# from $options.xtremio_array_busy_retry_count
{{ if not $options.xtremio_array_busy_retry_count }}#{{ end }}xtremio_array_busy_retry_count = {{ $options.xtremio_array_busy_retry_count | default "5" }}

# Interval between retries in case array is busy (integer value)
# from $options.xtremio_array_busy_retry_interval
{{ if not $options.xtremio_array_busy_retry_interval }}#{{ end }}xtremio_array_busy_retry_interval = {{ $options.xtremio_array_busy_retry_interval | default "5" }}

# Number of volumes created from each cached glance image (integer
# value)
# from $options.xtremio_volumes_per_glance_cache
{{ if not $options.xtremio_volumes_per_glance_cache }}#{{ end }}xtremio_volumes_per_glance_cache = {{ $options.xtremio_volumes_per_glance_cache | default "100" }}

# Serial number of storage system (string value)
# from $options.hitachi_serial_number
{{ if not $options.hitachi_serial_number }}#{{ end }}hitachi_serial_number = {{ $options.hitachi_serial_number | default "<None>" }}

# Name of an array unit (string value)
# from $options.hitachi_unit_name
{{ if not $options.hitachi_unit_name }}#{{ end }}hitachi_unit_name = {{ $options.hitachi_unit_name | default "<None>" }}

# Pool ID of storage system (integer value)
# from $options.hitachi_pool_id
{{ if not $options.hitachi_pool_id }}#{{ end }}hitachi_pool_id = {{ $options.hitachi_pool_id | default "<None>" }}

# Thin pool ID of storage system (integer value)
# from $options.hitachi_thin_pool_id
{{ if not $options.hitachi_thin_pool_id }}#{{ end }}hitachi_thin_pool_id = {{ $options.hitachi_thin_pool_id | default "<None>" }}

# Range of logical device of storage system (string value)
# from $options.hitachi_ldev_range
{{ if not $options.hitachi_ldev_range }}#{{ end }}hitachi_ldev_range = {{ $options.hitachi_ldev_range | default "<None>" }}

# Default copy method of storage system (string value)
# from $options.hitachi_default_copy_method
{{ if not $options.hitachi_default_copy_method }}#{{ end }}hitachi_default_copy_method = {{ $options.hitachi_default_copy_method | default "FULL" }}

# Copy speed of storage system (integer value)
# from $options.hitachi_copy_speed
{{ if not $options.hitachi_copy_speed }}#{{ end }}hitachi_copy_speed = {{ $options.hitachi_copy_speed | default "3" }}

# Interval to check copy (integer value)
# from $options.hitachi_copy_check_interval
{{ if not $options.hitachi_copy_check_interval }}#{{ end }}hitachi_copy_check_interval = {{ $options.hitachi_copy_check_interval | default "3" }}

# Interval to check copy asynchronously (integer value)
# from $options.hitachi_async_copy_check_interval
{{ if not $options.hitachi_async_copy_check_interval }}#{{ end }}hitachi_async_copy_check_interval = {{ $options.hitachi_async_copy_check_interval | default "10" }}

# Control port names for HostGroup or iSCSI Target (string value)
# from $options.hitachi_target_ports
{{ if not $options.hitachi_target_ports }}#{{ end }}hitachi_target_ports = {{ $options.hitachi_target_ports | default "<None>" }}

# Range of group number (string value)
# from $options.hitachi_group_range
{{ if not $options.hitachi_group_range }}#{{ end }}hitachi_group_range = {{ $options.hitachi_group_range | default "<None>" }}

# Request for creating HostGroup or iSCSI Target (boolean value)
# from $options.hitachi_group_request
{{ if not $options.hitachi_group_request }}#{{ end }}hitachi_group_request = {{ $options.hitachi_group_request | default "false" }}

# Infortrend raid pool name list. It is separated with comma. (string
# value)
# from $options.infortrend_pools_name
{{ if not $options.infortrend_pools_name }}#{{ end }}infortrend_pools_name = {{ $options.infortrend_pools_name | default "" }}

# The Infortrend CLI absolute path. By default, it is at
# /opt/bin/Infortrend/raidcmd_ESDS10.jar (string value)
# from $options.infortrend_cli_path
{{ if not $options.infortrend_cli_path }}#{{ end }}infortrend_cli_path = {{ $options.infortrend_cli_path | default "/opt/bin/Infortrend/raidcmd_ESDS10.jar" }}

# Maximum retry time for cli. Default is 5. (integer value)
# from $options.infortrend_cli_max_retries
{{ if not $options.infortrend_cli_max_retries }}#{{ end }}infortrend_cli_max_retries = {{ $options.infortrend_cli_max_retries | default "5" }}

# Default timeout for CLI copy operations in minutes. Support: migrate
# volume, create cloned volume and create volume from snapshot. By
# Default, it is 30 minutes. (integer value)
# from $options.infortrend_cli_timeout
{{ if not $options.infortrend_cli_timeout }}#{{ end }}infortrend_cli_timeout = {{ $options.infortrend_cli_timeout | default "30" }}

# Infortrend raid channel ID list on Slot A for OpenStack usage. It is
# separated with comma. By default, it is the channel 0~7. (string
# value)
# from $options.infortrend_slots_a_channels_id
{{ if not $options.infortrend_slots_a_channels_id }}#{{ end }}infortrend_slots_a_channels_id = {{ $options.infortrend_slots_a_channels_id | default "0,1,2,3,4,5,6,7" }}

# Infortrend raid channel ID list on Slot B for OpenStack usage. It is
# separated with comma. By default, it is the channel 0~7. (string
# value)
# from $options.infortrend_slots_b_channels_id
{{ if not $options.infortrend_slots_b_channels_id }}#{{ end }}infortrend_slots_b_channels_id = {{ $options.infortrend_slots_b_channels_id | default "0,1,2,3,4,5,6,7" }}

# Let the volume use specific provisioning. By default, it is the full
# provisioning. The supported options are full or thin. (string value)
# from $options.infortrend_provisioning
{{ if not $options.infortrend_provisioning }}#{{ end }}infortrend_provisioning = {{ $options.infortrend_provisioning | default "full" }}

# Let the volume use specific tiering level. By default, it is the
# level 0. The supported levels are 0,2,3,4. (string value)
# from $options.infortrend_tiering
{{ if not $options.infortrend_tiering }}#{{ end }}infortrend_tiering = {{ $options.infortrend_tiering | default "0" }}

# DEPRECATED: Legacy configuration file for HNAS iSCSI Cinder plugin.
# This is not needed if you fill all configuration on cinder.conf
# (string value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# from $options.hds_hnas_iscsi_config_file
{{ if not $options.hds_hnas_iscsi_config_file }}#{{ end }}hds_hnas_iscsi_config_file = {{ $options.hds_hnas_iscsi_config_file | default "/opt/hds/hnas/cinder_iscsi_conf.xml" }}

# Whether the chap authentication is enabled in the iSCSI target or
# not. (boolean value)
# from $options.hnas_chap_enabled
{{ if not $options.hnas_chap_enabled }}#{{ end }}hnas_chap_enabled = {{ $options.hnas_chap_enabled | default "true" }}

# Service 0 iSCSI IP (IP address value)
# from $options.hnas_svc0_iscsi_ip
{{ if not $options.hnas_svc0_iscsi_ip }}#{{ end }}hnas_svc0_iscsi_ip = {{ $options.hnas_svc0_iscsi_ip | default "<None>" }}

# Service 1 iSCSI IP (IP address value)
# from $options.hnas_svc1_iscsi_ip
{{ if not $options.hnas_svc1_iscsi_ip }}#{{ end }}hnas_svc1_iscsi_ip = {{ $options.hnas_svc1_iscsi_ip | default "<None>" }}

# Service 2 iSCSI IP (IP address value)
# from $options.hnas_svc2_iscsi_ip
{{ if not $options.hnas_svc2_iscsi_ip }}#{{ end }}hnas_svc2_iscsi_ip = {{ $options.hnas_svc2_iscsi_ip | default "<None>" }}

# Service 3 iSCSI IP (IP address value)
# from $options.hnas_svc3_iscsi_ip
{{ if not $options.hnas_svc3_iscsi_ip }}#{{ end }}hnas_svc3_iscsi_ip = {{ $options.hnas_svc3_iscsi_ip | default "<None>" }}

# The name of ceph cluster (string value)
# from $options.rbd_cluster_name
{{ if not $options.rbd_cluster_name }}#{{ end }}rbd_cluster_name = {{ $options.rbd_cluster_name | default "ceph" }}

# The RADOS pool where rbd volumes are stored (string value)
# from $options.rbd_pool
{{ if not $options.rbd_pool }}#{{ end }}rbd_pool = {{ $options.rbd_pool | default "rbd" }}

# The RADOS client name for accessing rbd volumes - only set when
# using cephx authentication (string value)
# from $options.rbd_user
{{ if not $options.rbd_user }}#{{ end }}rbd_user = {{ $options.rbd_user | default "<None>" }}

# Path to the ceph configuration file (string value)
# from $options.rbd_ceph_conf
{{ if not $options.rbd_ceph_conf }}#{{ end }}rbd_ceph_conf = {{ $options.rbd_ceph_conf | default "" }}

# Flatten volumes created from snapshots to remove dependency from
# volume to snapshot (boolean value)
# from $options.rbd_flatten_volume_from_snapshot
{{ if not $options.rbd_flatten_volume_from_snapshot }}#{{ end }}rbd_flatten_volume_from_snapshot = {{ $options.rbd_flatten_volume_from_snapshot | default "false" }}

# The libvirt uuid of the secret for the rbd_user volumes (string
# value)
# from $options.rbd_secret_uuid
{{ if not $options.rbd_secret_uuid }}#{{ end }}rbd_secret_uuid = {{ $options.rbd_secret_uuid | default "<None>" }}

# Directory where temporary image files are stored when the volume
# driver does not write them directly to the volume.  Warning: this
# option is now deprecated, please use image_conversion_dir instead.
# (string value)
# from $options.volume_tmp_dir
{{ if not $options.volume_tmp_dir }}#{{ end }}volume_tmp_dir = {{ $options.volume_tmp_dir | default "<None>" }}

# Maximum number of nested volume clones that are taken before a
# flatten occurs. Set to 0 to disable cloning. (integer value)
# from $options.rbd_max_clone_depth
{{ if not $options.rbd_max_clone_depth }}#{{ end }}rbd_max_clone_depth = {{ $options.rbd_max_clone_depth | default "5" }}

# Volumes will be chunked into objects of this size (in megabytes).
# (integer value)
# from $options.rbd_store_chunk_size
{{ if not $options.rbd_store_chunk_size }}#{{ end }}rbd_store_chunk_size = {{ $options.rbd_store_chunk_size | default "4" }}

# Timeout value (in seconds) used when connecting to ceph cluster. If
# value < 0, no timeout is set and default librados value is used.
# (integer value)
# from $options.rados_connect_timeout
{{ if not $options.rados_connect_timeout }}#{{ end }}rados_connect_timeout = {{ $options.rados_connect_timeout | default "-1" }}

# Number of retries if connection to ceph cluster failed. (integer
# value)
# from $options.rados_connection_retries
{{ if not $options.rados_connection_retries }}#{{ end }}rados_connection_retries = {{ $options.rados_connection_retries | default "3" }}

# Interval value (in seconds) between connection retries to ceph
# cluster. (integer value)
# from $options.rados_connection_interval
{{ if not $options.rados_connection_interval }}#{{ end }}rados_connection_interval = {{ $options.rados_connection_interval | default "5" }}

# The hostname (or IP address) for the storage system (string value)
# from $options.tintri_server_hostname
{{ if not $options.tintri_server_hostname }}#{{ end }}tintri_server_hostname = {{ $options.tintri_server_hostname | default "<None>" }}

# User name for the storage system (string value)
# from $options.tintri_server_username
{{ if not $options.tintri_server_username }}#{{ end }}tintri_server_username = {{ $options.tintri_server_username | default "<None>" }}

# Password for the storage system (string value)
# from $options.tintri_server_password
{{ if not $options.tintri_server_password }}#{{ end }}tintri_server_password = {{ $options.tintri_server_password | default "<None>" }}

# API version for the storage system (string value)
# from $options.tintri_api_version
{{ if not $options.tintri_api_version }}#{{ end }}tintri_api_version = {{ $options.tintri_api_version | default "v310" }}

# Delete unused image snapshots older than mentioned days (integer
# value)
# from $options.tintri_image_cache_expiry_days
{{ if not $options.tintri_image_cache_expiry_days }}#{{ end }}tintri_image_cache_expiry_days = {{ $options.tintri_image_cache_expiry_days | default "30" }}

# Path to image nfs shares file (string value)
# from $options.tintri_image_shares_config
{{ if not $options.tintri_image_shares_config }}#{{ end }}tintri_image_shares_config = {{ $options.tintri_image_shares_config | default "<None>" }}

# Instance numbers for HORCM (string value)
# from $options.hitachi_horcm_numbers
{{ if not $options.hitachi_horcm_numbers }}#{{ end }}hitachi_horcm_numbers = {{ $options.hitachi_horcm_numbers | default "200,201" }}

# Username of storage system for HORCM (string value)
# from $options.hitachi_horcm_user
{{ if not $options.hitachi_horcm_user }}#{{ end }}hitachi_horcm_user = {{ $options.hitachi_horcm_user | default "<None>" }}

# Password of storage system for HORCM (string value)
# from $options.hitachi_horcm_password
{{ if not $options.hitachi_horcm_password }}#{{ end }}hitachi_horcm_password = {{ $options.hitachi_horcm_password | default "<None>" }}

# Add to HORCM configuration (boolean value)
# from $options.hitachi_horcm_add_conf
{{ if not $options.hitachi_horcm_add_conf }}#{{ end }}hitachi_horcm_add_conf = {{ $options.hitachi_horcm_add_conf | default "true" }}

# Timeout until a resource lock is released, in seconds. The value
# must be between 0 and 7200. (integer value)
# from $options.hitachi_horcm_resource_lock_timeout
{{ if not $options.hitachi_horcm_resource_lock_timeout }}#{{ end }}hitachi_horcm_resource_lock_timeout = {{ $options.hitachi_horcm_resource_lock_timeout | default "600" }}

# Comma separated list of storage system storage pools for volumes.
# (list value)
# from $options.storwize_svc_volpool_name
{{ if not $options.storwize_svc_volpool_name }}#{{ end }}storwize_svc_volpool_name = {{ $options.storwize_svc_volpool_name | default "volpool" }}

# Storage system space-efficiency parameter for volumes (percentage)
# (integer value)
# Minimum value: -1
# Maximum value: 100
# from $options.storwize_svc_vol_rsize
{{ if not $options.storwize_svc_vol_rsize }}#{{ end }}storwize_svc_vol_rsize = {{ $options.storwize_svc_vol_rsize | default "2" }}

# Storage system threshold for volume capacity warnings (percentage)
# (integer value)
# Minimum value: -1
# Maximum value: 100
# from $options.storwize_svc_vol_warning
{{ if not $options.storwize_svc_vol_warning }}#{{ end }}storwize_svc_vol_warning = {{ $options.storwize_svc_vol_warning | default "0" }}

# Storage system autoexpand parameter for volumes (True/False)
# (boolean value)
# from $options.storwize_svc_vol_autoexpand
{{ if not $options.storwize_svc_vol_autoexpand }}#{{ end }}storwize_svc_vol_autoexpand = {{ $options.storwize_svc_vol_autoexpand | default "true" }}

# Storage system grain size parameter for volumes (32/64/128/256)
# (integer value)
# from $options.storwize_svc_vol_grainsize
{{ if not $options.storwize_svc_vol_grainsize }}#{{ end }}storwize_svc_vol_grainsize = {{ $options.storwize_svc_vol_grainsize | default "256" }}

# Storage system compression option for volumes (boolean value)
# from $options.storwize_svc_vol_compression
{{ if not $options.storwize_svc_vol_compression }}#{{ end }}storwize_svc_vol_compression = {{ $options.storwize_svc_vol_compression | default "false" }}

# Enable Easy Tier for volumes (boolean value)
# from $options.storwize_svc_vol_easytier
{{ if not $options.storwize_svc_vol_easytier }}#{{ end }}storwize_svc_vol_easytier = {{ $options.storwize_svc_vol_easytier | default "true" }}

# The I/O group in which to allocate volumes (integer value)
# from $options.storwize_svc_vol_iogrp
{{ if not $options.storwize_svc_vol_iogrp }}#{{ end }}storwize_svc_vol_iogrp = {{ $options.storwize_svc_vol_iogrp | default "0" }}

# Maximum number of seconds to wait for FlashCopy to be prepared.
# (integer value)
# Minimum value: 1
# Maximum value: 600
# from $options.storwize_svc_flashcopy_timeout
{{ if not $options.storwize_svc_flashcopy_timeout }}#{{ end }}storwize_svc_flashcopy_timeout = {{ $options.storwize_svc_flashcopy_timeout | default "120" }}

# DEPRECATED: This option no longer has any affect. It is deprecated
# and will be removed in the next release. (boolean value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# from $options.storwize_svc_multihostmap_enabled
{{ if not $options.storwize_svc_multihostmap_enabled }}#{{ end }}storwize_svc_multihostmap_enabled = {{ $options.storwize_svc_multihostmap_enabled | default "true" }}

# Allow tenants to specify QOS on create (boolean value)
# from $options.storwize_svc_allow_tenant_qos
{{ if not $options.storwize_svc_allow_tenant_qos }}#{{ end }}storwize_svc_allow_tenant_qos = {{ $options.storwize_svc_allow_tenant_qos | default "false" }}

# If operating in stretched cluster mode, specify the name of the pool
# in which mirrored copies are stored.Example: "pool2" (string value)
# from $options.storwize_svc_stretched_cluster_partner
{{ if not $options.storwize_svc_stretched_cluster_partner }}#{{ end }}storwize_svc_stretched_cluster_partner = {{ $options.storwize_svc_stretched_cluster_partner | default "<None>" }}

# Specifies secondary management IP or hostname to be used if san_ip
# is invalid or becomes inaccessible. (string value)
# from $options.storwize_san_secondary_ip
{{ if not $options.storwize_san_secondary_ip }}#{{ end }}storwize_san_secondary_ip = {{ $options.storwize_san_secondary_ip | default "<None>" }}

# Specifies that the volume not be formatted during creation. (boolean
# value)
# from $options.storwize_svc_vol_nofmtdisk
{{ if not $options.storwize_svc_vol_nofmtdisk }}#{{ end }}storwize_svc_vol_nofmtdisk = {{ $options.storwize_svc_vol_nofmtdisk | default "false" }}

# Specifies the Storwize FlashCopy copy rate to be used when creating
# a full volume copy. The default is rate is 50, and the valid rates
# are 1-100. (integer value)
# Minimum value: 1
# Maximum value: 100
# from $options.storwize_svc_flashcopy_rate
{{ if not $options.storwize_svc_flashcopy_rate }}#{{ end }}storwize_svc_flashcopy_rate = {{ $options.storwize_svc_flashcopy_rate | default "50" }}

# Request for FC Zone creating HostGroup (boolean value)
# from $options.hitachi_zoning_request
{{ if not $options.hitachi_zoning_request }}#{{ end }}hitachi_zoning_request = {{ $options.hitachi_zoning_request | default "false" }}

# The configuration file for the Cinder Huawei driver. (string value)
# from $options.cinder_huawei_conf_file
{{ if not $options.cinder_huawei_conf_file }}#{{ end }}cinder_huawei_conf_file = {{ $options.cinder_huawei_conf_file | default "/etc/cinder/cinder_huawei_conf.xml" }}

# The remote device hypermetro will use. (string value)
# from $options.hypermetro_devices
{{ if not $options.hypermetro_devices }}#{{ end }}hypermetro_devices = {{ $options.hypermetro_devices | default "<None>" }}

# The remote metro device san user. (string value)
# from $options.metro_san_user
{{ if not $options.metro_san_user }}#{{ end }}metro_san_user = {{ $options.metro_san_user | default "<None>" }}

# The remote metro device san password. (string value)
# from $options.metro_san_password
{{ if not $options.metro_san_password }}#{{ end }}metro_san_password = {{ $options.metro_san_password | default "<None>" }}

# The remote metro device domain name. (string value)
# from $options.metro_domain_name
{{ if not $options.metro_domain_name }}#{{ end }}metro_domain_name = {{ $options.metro_domain_name | default "<None>" }}

# The remote metro device request url. (string value)
# from $options.metro_san_address
{{ if not $options.metro_san_address }}#{{ end }}metro_san_address = {{ $options.metro_san_address | default "<None>" }}

# The remote metro device pool names. (string value)
# from $options.metro_storage_pools
{{ if not $options.metro_storage_pools }}#{{ end }}metro_storage_pools = {{ $options.metro_storage_pools | default "<None>" }}

# Volume on Synology storage to be used for creating lun. (string
# value)
# from $options.synology_pool_name
{{ if not $options.synology_pool_name }}#{{ end }}synology_pool_name = {{ $options.synology_pool_name | default "" }}

# Management port for Synology storage. (port value)
# Minimum value: 0
# Maximum value: 65535
# from $options.synology_admin_port
{{ if not $options.synology_admin_port }}#{{ end }}synology_admin_port = {{ $options.synology_admin_port | default "5000" }}

# Administrator of Synology storage. (string value)
# from $options.synology_username
{{ if not $options.synology_username }}#{{ end }}synology_username = {{ $options.synology_username | default "admin" }}

# Password of administrator for logging in Synology storage. (string
# value)
# from $options.synology_password
{{ if not $options.synology_password }}#{{ end }}synology_password = {{ $options.synology_password | default "" }}

# Do certificate validation or not if $driver_use_ssl is True (boolean
# value)
# from $options.synology_ssl_verify
{{ if not $options.synology_ssl_verify }}#{{ end }}synology_ssl_verify = {{ $options.synology_ssl_verify | default "true" }}

# One time password of administrator for logging in Synology storage
# if OTP is enabled. (string value)
# from $options.synology_one_time_pass
{{ if not $options.synology_one_time_pass }}#{{ end }}synology_one_time_pass = {{ $options.synology_one_time_pass | default "<None>" }}

# Device id for skip one time password check for logging in Synology
# storage if OTP is enabled. (string value)
# from $options.synology_device_id
{{ if not $options.synology_device_id }}#{{ end }}synology_device_id = {{ $options.synology_device_id | default "<None>" }}

# Storage Center System Serial Number (integer value)
# from $options.dell_sc_ssn
{{ if not $options.dell_sc_ssn }}#{{ end }}dell_sc_ssn = {{ $options.dell_sc_ssn | default "64702" }}

# Dell API port (port value)
# Minimum value: 0
# Maximum value: 65535
# from $options.dell_sc_api_port
{{ if not $options.dell_sc_api_port }}#{{ end }}dell_sc_api_port = {{ $options.dell_sc_api_port | default "3033" }}

# Name of the server folder to use on the Storage Center (string
# value)
# from $options.dell_sc_server_folder
{{ if not $options.dell_sc_server_folder }}#{{ end }}dell_sc_server_folder = {{ $options.dell_sc_server_folder | default "openstack" }}

# Name of the volume folder to use on the Storage Center (string
# value)
# from $options.dell_sc_volume_folder
{{ if not $options.dell_sc_volume_folder }}#{{ end }}dell_sc_volume_folder = {{ $options.dell_sc_volume_folder | default "openstack" }}

# Enable HTTPS SC certificate verification (boolean value)
# from $options.dell_sc_verify_cert
{{ if not $options.dell_sc_verify_cert }}#{{ end }}dell_sc_verify_cert = {{ $options.dell_sc_verify_cert | default "false" }}

# IP address of secondary DSM controller (string value)
# from $options.secondary_san_ip
{{ if not $options.secondary_san_ip }}#{{ end }}secondary_san_ip = {{ $options.secondary_san_ip | default "" }}

# Secondary DSM user name (string value)
# from $options.secondary_san_login
{{ if not $options.secondary_san_login }}#{{ end }}secondary_san_login = {{ $options.secondary_san_login | default "Admin" }}

# Secondary DSM user password name (string value)
# from $options.secondary_san_password
{{ if not $options.secondary_san_password }}#{{ end }}secondary_san_password = {{ $options.secondary_san_password | default "" }}

# Secondary Dell API port (port value)
# Minimum value: 0
# Maximum value: 65535
# from $options.secondary_sc_api_port
{{ if not $options.secondary_sc_api_port }}#{{ end }}secondary_sc_api_port = {{ $options.secondary_sc_api_port | default "3033" }}

# Domain IP to be excluded from iSCSI returns. (IP address value)
# from $options.excluded_domain_ip (multiopt)
{{ if not $options.excluded_domain_ip }}#excluded_domain_ip = {{ $options.excluded_domain_ip | default "<None>" }}{{ else }}{{ range $options.excluded_domain_ip }}excluded_domain_ip = {{ . }}{{ end }}{{ end }}

# Server OS type to use when creating a new server on the Storage
# Center. (string value)
# from $options.dell_server_os
{{ if not $options.dell_server_os }}#{{ end }}dell_server_os = {{ $options.dell_server_os | default "Red Hat Linux 6.x" }}

# IP address/hostname of Blockbridge API. (string value)
# from $options.blockbridge_api_host
{{ if not $options.blockbridge_api_host }}#{{ end }}blockbridge_api_host = {{ $options.blockbridge_api_host | default "<None>" }}

# Override HTTPS port to connect to Blockbridge API server. (integer
# value)
# from $options.blockbridge_api_port
{{ if not $options.blockbridge_api_port }}#{{ end }}blockbridge_api_port = {{ $options.blockbridge_api_port | default "<None>" }}

# Blockbridge API authentication scheme (token or password) (string
# value)
# Allowed values: token, password
# from $options.blockbridge_auth_scheme
{{ if not $options.blockbridge_auth_scheme }}#{{ end }}blockbridge_auth_scheme = {{ $options.blockbridge_auth_scheme | default "token" }}

# Blockbridge API token (for auth scheme 'token') (string value)
# from $options.blockbridge_auth_token
{{ if not $options.blockbridge_auth_token }}#{{ end }}blockbridge_auth_token = {{ $options.blockbridge_auth_token | default "<None>" }}

# Blockbridge API user (for auth scheme 'password') (string value)
# from $options.blockbridge_auth_user
{{ if not $options.blockbridge_auth_user }}#{{ end }}blockbridge_auth_user = {{ $options.blockbridge_auth_user | default "<None>" }}

# Blockbridge API password (for auth scheme 'password') (string value)
# from $options.blockbridge_auth_password
{{ if not $options.blockbridge_auth_password }}#{{ end }}blockbridge_auth_password = {{ $options.blockbridge_auth_password | default "<None>" }}

# Defines the set of exposed pools and their associated backend query
# strings (dict value)
# from $options.blockbridge_pools
{{ if not $options.blockbridge_pools }}#{{ end }}blockbridge_pools = {{ $options.blockbridge_pools | default "OpenStack:+openstack" }}

# Default pool name if unspecified. (string value)
# from $options.blockbridge_default_pool
{{ if not $options.blockbridge_default_pool }}#{{ end }}blockbridge_default_pool = {{ $options.blockbridge_default_pool | default "<None>" }}

# Data path IP address (string value)
# from $options.zfssa_data_ip
{{ if not $options.zfssa_data_ip }}#{{ end }}zfssa_data_ip = {{ $options.zfssa_data_ip | default "<None>" }}

# HTTPS port number (string value)
# from $options.zfssa_https_port
{{ if not $options.zfssa_https_port }}#{{ end }}zfssa_https_port = {{ $options.zfssa_https_port | default "443" }}

# Options to be passed while mounting share over nfs (string value)
# from $options.zfssa_nfs_mount_options
{{ if not $options.zfssa_nfs_mount_options }}#{{ end }}zfssa_nfs_mount_options = {{ $options.zfssa_nfs_mount_options | default "" }}

# Storage pool name. (string value)
# from $options.zfssa_nfs_pool
{{ if not $options.zfssa_nfs_pool }}#{{ end }}zfssa_nfs_pool = {{ $options.zfssa_nfs_pool | default "" }}

# Project name. (string value)
# from $options.zfssa_nfs_project
{{ if not $options.zfssa_nfs_project }}#{{ end }}zfssa_nfs_project = {{ $options.zfssa_nfs_project | default "NFSProject" }}

# Share name. (string value)
# from $options.zfssa_nfs_share
{{ if not $options.zfssa_nfs_share }}#{{ end }}zfssa_nfs_share = {{ $options.zfssa_nfs_share | default "nfs_share" }}

# Data compression. (string value)
# Allowed values: off, lzjb, gzip-2, gzip, gzip-9
# from $options.zfssa_nfs_share_compression
{{ if not $options.zfssa_nfs_share_compression }}#{{ end }}zfssa_nfs_share_compression = {{ $options.zfssa_nfs_share_compression | default "off" }}

# Synchronous write bias-latency, throughput. (string value)
# Allowed values: latency, throughput
# from $options.zfssa_nfs_share_logbias
{{ if not $options.zfssa_nfs_share_logbias }}#{{ end }}zfssa_nfs_share_logbias = {{ $options.zfssa_nfs_share_logbias | default "latency" }}

# Name of directory inside zfssa_nfs_share where cache volumes are
# stored. (string value)
# from $options.zfssa_cache_directory
{{ if not $options.zfssa_cache_directory }}#{{ end }}zfssa_cache_directory = {{ $options.zfssa_cache_directory | default "os-cinder-cache" }}

# DEPRECATED: If volume-type name contains this substring nodedup
# volume will be created, otherwise dedup volume wil be created.
# (string value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: This option is deprecated in favour of
# 'kaminario:thin_prov_type' in extra-specs and will be removed in the
# next release.
# from $options.kaminario_nodedup_substring
{{ if not $options.kaminario_nodedup_substring }}#{{ end }}kaminario_nodedup_substring = {{ $options.kaminario_nodedup_substring | default "K2-nodedup" }}

# The IP of DMS client socket server (IP address value)
# from $options.disco_client
{{ if not $options.disco_client }}#{{ end }}disco_client = {{ $options.disco_client | default "127.0.0.1" }}

# The port to connect DMS client socket server (port value)
# Minimum value: 0
# Maximum value: 65535
# from $options.disco_client_port
{{ if not $options.disco_client_port }}#{{ end }}disco_client_port = {{ $options.disco_client_port | default "9898" }}

# Path to the wsdl file to communicate with DISCO request manager
# (string value)
# from $options.disco_wsdl_path
{{ if not $options.disco_wsdl_path }}#{{ end }}disco_wsdl_path = {{ $options.disco_wsdl_path | default "/etc/cinder/DISCOService.wsdl" }}

# Prefix before volume name to differentiate DISCO volume created
# through openstack and the other ones (string value)
# from $options.volume_name_prefix
{{ if not $options.volume_name_prefix }}#{{ end }}volume_name_prefix = {{ $options.volume_name_prefix | default "openstack-" }}

# How long we check whether a snapshot is finished before we give up
# (integer value)
# from $options.snapshot_check_timeout
{{ if not $options.snapshot_check_timeout }}#{{ end }}snapshot_check_timeout = {{ $options.snapshot_check_timeout | default "3600" }}

# How long we check whether a restore is finished before we give up
# (integer value)
# from $options.restore_check_timeout
{{ if not $options.restore_check_timeout }}#{{ end }}restore_check_timeout = {{ $options.restore_check_timeout | default "3600" }}

# How long we check whether a clone is finished before we give up
# (integer value)
# from $options.clone_check_timeout
{{ if not $options.clone_check_timeout }}#{{ end }}clone_check_timeout = {{ $options.clone_check_timeout | default "3600" }}

# How long we wait before retrying to get an item detail (integer
# value)
# from $options.retry_interval
{{ if not $options.retry_interval }}#{{ end }}retry_interval = {{ $options.retry_interval | default "1" }}

# Space network name to use for data transfer (string value)
# from $options.hgst_net
{{ if not $options.hgst_net }}#{{ end }}hgst_net = {{ $options.hgst_net | default "Net 1 (IPv4)" }}

# Comma separated list of Space storage servers:devices. ex:
# os1_stor:gbd0,os2_stor:gbd0 (string value)
# from $options.hgst_storage_servers
{{ if not $options.hgst_storage_servers }}#{{ end }}hgst_storage_servers = {{ $options.hgst_storage_servers | default "os:gbd0" }}

# Should spaces be redundantly stored (1/0) (string value)
# from $options.hgst_redundancy
{{ if not $options.hgst_redundancy }}#{{ end }}hgst_redundancy = {{ $options.hgst_redundancy | default "0" }}

# User to own created spaces (string value)
# from $options.hgst_space_user
{{ if not $options.hgst_space_user }}#{{ end }}hgst_space_user = {{ $options.hgst_space_user | default "root" }}

# Group to own created spaces (string value)
# from $options.hgst_space_group
{{ if not $options.hgst_space_group }}#{{ end }}hgst_space_group = {{ $options.hgst_space_group | default "disk" }}

# UNIX mode for created spaces (string value)
# from $options.hgst_space_mode
{{ if not $options.hgst_space_mode }}#{{ end }}hgst_space_mode = {{ $options.hgst_space_mode | default "0600" }}

# DEPRECATED: This option no longer has any affect. It is deprecated
# and will be removed in the next release. (boolean value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# from $options.flashsystem_multipath_enabled
{{ if not $options.flashsystem_multipath_enabled }}#{{ end }}flashsystem_multipath_enabled = {{ $options.flashsystem_multipath_enabled | default "false" }}

# DPL pool uuid in which DPL volumes are stored. (string value)
# from $options.dpl_pool
{{ if not $options.dpl_pool }}#{{ end }}dpl_pool = {{ $options.dpl_pool | default "" }}

# DPL port number. (port value)
# Minimum value: 0
# Maximum value: 65535
# from $options.dpl_port
{{ if not $options.dpl_port }}#{{ end }}dpl_port = {{ $options.dpl_port | default "8357" }}

# Request for FC Zone creating host group (boolean value)
# Deprecated group/name - [BACKEND]/hpxp_zoning_request
# from $options.hpexp_zoning_request
{{ if not $options.hpexp_zoning_request }}#{{ end }}hpexp_zoning_request = {{ $options.hpexp_zoning_request | default "false" }}

# Type of storage command line interface (string value)
# Deprecated group/name - [BACKEND]/hpxp_storage_cli
# from $options.hpexp_storage_cli
{{ if not $options.hpexp_storage_cli }}#{{ end }}hpexp_storage_cli = {{ $options.hpexp_storage_cli | default "<None>" }}

# ID of storage system (string value)
# Deprecated group/name - [BACKEND]/hpxp_storage_id
# from $options.hpexp_storage_id
{{ if not $options.hpexp_storage_id }}#{{ end }}hpexp_storage_id = {{ $options.hpexp_storage_id | default "<None>" }}

# Pool of storage system (string value)
# Deprecated group/name - [BACKEND]/hpxp_pool
# from $options.hpexp_pool
{{ if not $options.hpexp_pool }}#{{ end }}hpexp_pool = {{ $options.hpexp_pool | default "<None>" }}

# Thin pool of storage system (string value)
# Deprecated group/name - [BACKEND]/hpxp_thin_pool
# from $options.hpexp_thin_pool
{{ if not $options.hpexp_thin_pool }}#{{ end }}hpexp_thin_pool = {{ $options.hpexp_thin_pool | default "<None>" }}

# Logical device range of storage system (string value)
# Deprecated group/name - [BACKEND]/hpxp_ldev_range
# from $options.hpexp_ldev_range
{{ if not $options.hpexp_ldev_range }}#{{ end }}hpexp_ldev_range = {{ $options.hpexp_ldev_range | default "<None>" }}

# Default copy method of storage system. There are two valid values:
# "FULL" specifies that a full copy; "THIN" specifies that a thin
# copy. Default value is "FULL" (string value)
# Deprecated group/name - [BACKEND]/hpxp_default_copy_method
# from $options.hpexp_default_copy_method
{{ if not $options.hpexp_default_copy_method }}#{{ end }}hpexp_default_copy_method = {{ $options.hpexp_default_copy_method | default "FULL" }}

# Copy speed of storage system (integer value)
# Deprecated group/name - [BACKEND]/hpxp_copy_speed
# from $options.hpexp_copy_speed
{{ if not $options.hpexp_copy_speed }}#{{ end }}hpexp_copy_speed = {{ $options.hpexp_copy_speed | default "3" }}

# Interval to check copy (integer value)
# Deprecated group/name - [BACKEND]/hpxp_copy_check_interval
# from $options.hpexp_copy_check_interval
{{ if not $options.hpexp_copy_check_interval }}#{{ end }}hpexp_copy_check_interval = {{ $options.hpexp_copy_check_interval | default "3" }}

# Interval to check copy asynchronously (integer value)
# Deprecated group/name - [BACKEND]/hpxp_async_copy_check_interval
# from $options.hpexp_async_copy_check_interval
{{ if not $options.hpexp_async_copy_check_interval }}#{{ end }}hpexp_async_copy_check_interval = {{ $options.hpexp_async_copy_check_interval | default "10" }}

# Target port names for host group or iSCSI target (list value)
# Deprecated group/name - [BACKEND]/hpxp_target_ports
# from $options.hpexp_target_ports
{{ if not $options.hpexp_target_ports }}#{{ end }}hpexp_target_ports = {{ $options.hpexp_target_ports | default "<None>" }}

# Target port names of compute node for host group or iSCSI target
# (list value)
# Deprecated group/name - [BACKEND]/hpxp_compute_target_ports
# from $options.hpexp_compute_target_ports
{{ if not $options.hpexp_compute_target_ports }}#{{ end }}hpexp_compute_target_ports = {{ $options.hpexp_compute_target_ports | default "<None>" }}

# Request for creating host group or iSCSI target (boolean value)
# Deprecated group/name - [BACKEND]/hpxp_group_request
# from $options.hpexp_group_request
{{ if not $options.hpexp_group_request }}#{{ end }}hpexp_group_request = {{ $options.hpexp_group_request | default "false" }}

# Instance numbers for HORCM (list value)
# Deprecated group/name - [BACKEND]/hpxp_horcm_numbers
# from $options.hpexp_horcm_numbers
{{ if not $options.hpexp_horcm_numbers }}#{{ end }}hpexp_horcm_numbers = {{ $options.hpexp_horcm_numbers | default "200,201" }}

# Username of storage system for HORCM (string value)
# Deprecated group/name - [BACKEND]/hpxp_horcm_user
# from $options.hpexp_horcm_user
{{ if not $options.hpexp_horcm_user }}#{{ end }}hpexp_horcm_user = {{ $options.hpexp_horcm_user | default "<None>" }}

# Add to HORCM configuration (boolean value)
# Deprecated group/name - [BACKEND]/hpxp_horcm_add_conf
# from $options.hpexp_horcm_add_conf
{{ if not $options.hpexp_horcm_add_conf }}#{{ end }}hpexp_horcm_add_conf = {{ $options.hpexp_horcm_add_conf | default "true" }}

# Resource group name of storage system for HORCM (string value)
# Deprecated group/name - [BACKEND]/hpxp_horcm_resource_name
# from $options.hpexp_horcm_resource_name
{{ if not $options.hpexp_horcm_resource_name }}#{{ end }}hpexp_horcm_resource_name = {{ $options.hpexp_horcm_resource_name | default "meta_resource" }}

# Only discover a specific name of host group or iSCSI target (boolean
# value)
# Deprecated group/name - [BACKEND]/hpxp_horcm_name_only_discovery
# from $options.hpexp_horcm_name_only_discovery
{{ if not $options.hpexp_horcm_name_only_discovery }}#{{ end }}hpexp_horcm_name_only_discovery = {{ $options.hpexp_horcm_name_only_discovery | default "false" }}

# Add CHAP user (boolean value)
# from $options.hitachi_add_chap_user
{{ if not $options.hitachi_add_chap_user }}#{{ end }}hitachi_add_chap_user = {{ $options.hitachi_add_chap_user | default "false" }}

# iSCSI authentication method (string value)
# from $options.hitachi_auth_method
{{ if not $options.hitachi_auth_method }}#{{ end }}hitachi_auth_method = {{ $options.hitachi_auth_method | default "<None>" }}

# iSCSI authentication username (string value)
# from $options.hitachi_auth_user
{{ if not $options.hitachi_auth_user }}#{{ end }}hitachi_auth_user = {{ $options.hitachi_auth_user | default "HBSD-CHAP-user" }}

# iSCSI authentication password (string value)
# from $options.hitachi_auth_password
{{ if not $options.hitachi_auth_password }}#{{ end }}hitachi_auth_password = {{ $options.hitachi_auth_password | default "HBSD-CHAP-password" }}

# Default iSCSI Port ID of FlashSystem. (Default port is 0.) (integer
# value)
# from $options.flashsystem_iscsi_portid
{{ if not $options.flashsystem_iscsi_portid }}#{{ end }}flashsystem_iscsi_portid = {{ $options.flashsystem_iscsi_portid | default "0" }}

# Create volumes in this pool (string value)
# from $options.tegile_default_pool
{{ if not $options.tegile_default_pool }}#{{ end }}tegile_default_pool = {{ $options.tegile_default_pool | default "<None>" }}

# Create volumes in this project (string value)
# from $options.tegile_default_project
{{ if not $options.tegile_default_project }}#{{ end }}tegile_default_project = {{ $options.tegile_default_project | default "<None>" }}

# Connection protocol should be FC. (Default is FC.) (string value)
# from $options.flashsystem_connection_protocol
{{ if not $options.flashsystem_connection_protocol }}#{{ end }}flashsystem_connection_protocol = {{ $options.flashsystem_connection_protocol | default "FC" }}

# Allows vdisk to multi host mapping. (Default is True) (boolean
# value)
# from $options.flashsystem_multihostmap_enabled
{{ if not $options.flashsystem_multihostmap_enabled }}#{{ end }}flashsystem_multihostmap_enabled = {{ $options.flashsystem_multihostmap_enabled | default "true" }}

# 3PAR WSAPI Server Url like https://<3par ip>:8080/api/v1 (string
# value)
# Deprecated group/name - [BACKEND]/hp3par_api_url
# from $options.hpe3par_api_url
{{ if not $options.hpe3par_api_url }}#{{ end }}hpe3par_api_url = {{ $options.hpe3par_api_url | default "" }}

# 3PAR username with the 'edit' role (string value)
# Deprecated group/name - [BACKEND]/hp3par_username
# from $options.hpe3par_username
{{ if not $options.hpe3par_username }}#{{ end }}hpe3par_username = {{ $options.hpe3par_username | default "" }}

# 3PAR password for the user specified in hpe3par_username (string
# value)
# Deprecated group/name - [BACKEND]/hp3par_password
# from $options.hpe3par_password
{{ if not $options.hpe3par_password }}#{{ end }}hpe3par_password = {{ $options.hpe3par_password | default "" }}

# List of the CPG(s) to use for volume creation (list value)
# Deprecated group/name - [BACKEND]/hp3par_cpg
# from $options.hpe3par_cpg
{{ if not $options.hpe3par_cpg }}#{{ end }}hpe3par_cpg = {{ $options.hpe3par_cpg | default "OpenStack" }}

# The CPG to use for Snapshots for volumes. If empty the userCPG will
# be used. (string value)
# Deprecated group/name - [BACKEND]/hp3par_cpg_snap
# from $options.hpe3par_cpg_snap
{{ if not $options.hpe3par_cpg_snap }}#{{ end }}hpe3par_cpg_snap = {{ $options.hpe3par_cpg_snap | default "" }}

# The time in hours to retain a snapshot.  You can't delete it before
# this expires. (string value)
# Deprecated group/name - [BACKEND]/hp3par_snapshot_retention
# from $options.hpe3par_snapshot_retention
{{ if not $options.hpe3par_snapshot_retention }}#{{ end }}hpe3par_snapshot_retention = {{ $options.hpe3par_snapshot_retention | default "" }}

# The time in hours when a snapshot expires  and is deleted.  This
# must be larger than expiration (string value)
# Deprecated group/name - [BACKEND]/hp3par_snapshot_expiration
# from $options.hpe3par_snapshot_expiration
{{ if not $options.hpe3par_snapshot_expiration }}#{{ end }}hpe3par_snapshot_expiration = {{ $options.hpe3par_snapshot_expiration | default "" }}

# Enable HTTP debugging to 3PAR (boolean value)
# Deprecated group/name - [BACKEND]/hp3par_debug
# from $options.hpe3par_debug
{{ if not $options.hpe3par_debug }}#{{ end }}hpe3par_debug = {{ $options.hpe3par_debug | default "false" }}

# List of target iSCSI addresses to use. (list value)
# Deprecated group/name - [BACKEND]/hp3par_iscsi_ips
# from $options.hpe3par_iscsi_ips
{{ if not $options.hpe3par_iscsi_ips }}#{{ end }}hpe3par_iscsi_ips = {{ $options.hpe3par_iscsi_ips | default "" }}

# Enable CHAP authentication for iSCSI connections. (boolean value)
# Deprecated group/name - [BACKEND]/hp3par_iscsi_chap_enabled
# from $options.hpe3par_iscsi_chap_enabled
{{ if not $options.hpe3par_iscsi_chap_enabled }}#{{ end }}hpe3par_iscsi_chap_enabled = {{ $options.hpe3par_iscsi_chap_enabled | default "false" }}

# Datera API port. (string value)
# from $options.datera_api_port
{{ if not $options.datera_api_port }}#{{ end }}datera_api_port = {{ $options.datera_api_port | default "7717" }}

# Datera API version. (string value)
# from $options.datera_api_version
{{ if not $options.datera_api_version }}#{{ end }}datera_api_version = {{ $options.datera_api_version | default "2" }}

# DEPRECATED: Number of replicas to create of an inode. (integer
# value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# from $options.datera_num_replicas
{{ if not $options.datera_num_replicas }}#{{ end }}datera_num_replicas = {{ $options.datera_num_replicas | default "3" }}

# Timeout for HTTP 503 retry messages (integer value)
# from $options.datera_503_timeout
{{ if not $options.datera_503_timeout }}#{{ end }}datera_503_timeout = {{ $options.datera_503_timeout | default "120" }}

# Interval between 503 retries (integer value)
# from $options.datera_503_interval
{{ if not $options.datera_503_interval }}#{{ end }}datera_503_interval = {{ $options.datera_503_interval | default "5" }}

# True to set function arg and return logging (boolean value)
# from $options.datera_debug
{{ if not $options.datera_debug }}#{{ end }}datera_debug = {{ $options.datera_debug | default "false" }}

# DEPRECATED: True to set acl 'allow_all' on volumes created (boolean
# value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# from $options.datera_acl_allow_all
{{ if not $options.datera_acl_allow_all }}#{{ end }}datera_acl_allow_all = {{ $options.datera_acl_allow_all | default "false" }}

# ONLY FOR DEBUG/TESTING PURPOSES
# True to set replica_count to 1 (boolean value)
# from $options.datera_debug_replica_count_override
{{ if not $options.datera_debug_replica_count_override }}#{{ end }}datera_debug_replica_count_override = {{ $options.datera_debug_replica_count_override | default "false" }}

# VPSA - Use ISER instead of iSCSI (boolean value)
# from $options.zadara_use_iser
{{ if not $options.zadara_use_iser }}#{{ end }}zadara_use_iser = {{ $options.zadara_use_iser | default "true" }}

# VPSA - Management Host name or IP address (string value)
# from $options.zadara_vpsa_host
{{ if not $options.zadara_vpsa_host }}#{{ end }}zadara_vpsa_host = {{ $options.zadara_vpsa_host | default "<None>" }}

# VPSA - Port number (port value)
# Minimum value: 0
# Maximum value: 65535
# from $options.zadara_vpsa_port
{{ if not $options.zadara_vpsa_port }}#{{ end }}zadara_vpsa_port = {{ $options.zadara_vpsa_port | default "<None>" }}

# VPSA - Use SSL connection (boolean value)
# from $options.zadara_vpsa_use_ssl
{{ if not $options.zadara_vpsa_use_ssl }}#{{ end }}zadara_vpsa_use_ssl = {{ $options.zadara_vpsa_use_ssl | default "false" }}

# VPSA - Username (string value)
# from $options.zadara_user
{{ if not $options.zadara_user }}#{{ end }}zadara_user = {{ $options.zadara_user | default "<None>" }}

# VPSA - Password (string value)
# from $options.zadara_password
{{ if not $options.zadara_password }}#{{ end }}zadara_password = {{ $options.zadara_password | default "<None>" }}

# VPSA - Storage Pool assigned for volumes (string value)
# from $options.zadara_vpsa_poolname
{{ if not $options.zadara_vpsa_poolname }}#{{ end }}zadara_vpsa_poolname = {{ $options.zadara_vpsa_poolname | default "<None>" }}

# VPSA - Default encryption policy for volumes (boolean value)
# from $options.zadara_vol_encrypt
{{ if not $options.zadara_vol_encrypt }}#{{ end }}zadara_vol_encrypt = {{ $options.zadara_vol_encrypt | default "false" }}

# VPSA - Default template for VPSA volume names (string value)
# from $options.zadara_vol_name_template
{{ if not $options.zadara_vol_name_template }}#{{ end }}zadara_vol_name_template = {{ $options.zadara_vol_name_template | default "OS_%s" }}

# VPSA - Attach snapshot policy for volumes (boolean value)
# from $options.zadara_default_snap_policy
{{ if not $options.zadara_default_snap_policy }}#{{ end }}zadara_default_snap_policy = {{ $options.zadara_default_snap_policy | default "false" }}

# List of all available devices (list value)
# from $options.available_devices
{{ if not $options.available_devices }}#{{ end }}available_devices = {{ $options.available_devices | default "" }}

# URL to the Quobyte volume e.g., quobyte://<DIR host>/<volume name>
# (string value)
# from $options.quobyte_volume_url
{{ if not $options.quobyte_volume_url }}#{{ end }}quobyte_volume_url = {{ $options.quobyte_volume_url | default "<None>" }}

# Path to a Quobyte Client configuration file. (string value)
# from $options.quobyte_client_cfg
{{ if not $options.quobyte_client_cfg }}#{{ end }}quobyte_client_cfg = {{ $options.quobyte_client_cfg | default "<None>" }}

# Create volumes as sparse files which take no space. If set to False,
# volume is created as regular file.In such case volume creation takes
# a lot of time. (boolean value)
# from $options.quobyte_sparsed_volumes
{{ if not $options.quobyte_sparsed_volumes }}#{{ end }}quobyte_sparsed_volumes = {{ $options.quobyte_sparsed_volumes | default "true" }}

# Create volumes as QCOW2 files rather than raw files. (boolean value)
# from $options.quobyte_qcow2_volumes
{{ if not $options.quobyte_qcow2_volumes }}#{{ end }}quobyte_qcow2_volumes = {{ $options.quobyte_qcow2_volumes | default "true" }}

# Base dir containing the mount point for the Quobyte volume. (string
# value)
# from $options.quobyte_mount_point_base
{{ if not $options.quobyte_mount_point_base }}#{{ end }}quobyte_mount_point_base = {{ $options.quobyte_mount_point_base | default "$state_path/mnt" }}

# File with the list of available vzstorage shares. (string value)
# from $options.vzstorage_shares_config
{{ if not $options.vzstorage_shares_config }}#{{ end }}vzstorage_shares_config = {{ $options.vzstorage_shares_config | default "/etc/cinder/vzstorage_shares" }}

# Create volumes as sparsed files which take no space rather than
# regular files when using raw format, in which case volume creation
# takes lot of time. (boolean value)
# from $options.vzstorage_sparsed_volumes
{{ if not $options.vzstorage_sparsed_volumes }}#{{ end }}vzstorage_sparsed_volumes = {{ $options.vzstorage_sparsed_volumes | default "true" }}

# Percent of ACTUAL usage of the underlying volume before no new
# volumes can be allocated to the volume destination. (floating point
# value)
# from $options.vzstorage_used_ratio
{{ if not $options.vzstorage_used_ratio }}#{{ end }}vzstorage_used_ratio = {{ $options.vzstorage_used_ratio | default "0.95" }}

# Base dir containing mount points for vzstorage shares. (string
# value)
# from $options.vzstorage_mount_point_base
{{ if not $options.vzstorage_mount_point_base }}#{{ end }}vzstorage_mount_point_base = {{ $options.vzstorage_mount_point_base | default "$state_path/mnt" }}

# Mount options passed to the vzstorage client. See section of the
# pstorage-mount man page for details. (list value)
# from $options.vzstorage_mount_options
{{ if not $options.vzstorage_mount_options }}#{{ end }}vzstorage_mount_options = {{ $options.vzstorage_mount_options | default "<None>" }}

# Default format that will be used when creating volumes if no volume
# format is specified. (string value)
# from $options.vzstorage_default_volume_format
{{ if not $options.vzstorage_default_volume_format }}#{{ end }}vzstorage_default_volume_format = {{ $options.vzstorage_default_volume_format | default "raw" }}

# File with the list of available NFS shares (string value)
# from $options.nfs_shares_config
{{ if not $options.nfs_shares_config }}#{{ end }}nfs_shares_config = {{ $options.nfs_shares_config | default "/etc/cinder/nfs_shares" }}

# Create volumes as sparsed files which take no space.If set to False
# volume is created as regular file.In such case volume creation takes
# a lot of time. (boolean value)
# from $options.nfs_sparsed_volumes
{{ if not $options.nfs_sparsed_volumes }}#{{ end }}nfs_sparsed_volumes = {{ $options.nfs_sparsed_volumes | default "true" }}

# Base dir containing mount points for NFS shares. (string value)
# from $options.nfs_mount_point_base
{{ if not $options.nfs_mount_point_base }}#{{ end }}nfs_mount_point_base = {{ $options.nfs_mount_point_base | default "$state_path/mnt" }}

# Mount options passed to the NFS client. See section of the NFS man
# page for details. (string value)
# from $options.nfs_mount_options
{{ if not $options.nfs_mount_options }}#{{ end }}nfs_mount_options = {{ $options.nfs_mount_options | default "<None>" }}

# The number of attempts to mount NFS shares before raising an error.
# At least one attempt will be made to mount an NFS share, regardless
# of the value specified. (integer value)
# from $options.nfs_mount_attempts
{{ if not $options.nfs_mount_attempts }}#{{ end }}nfs_mount_attempts = {{ $options.nfs_mount_attempts | default "3" }}

{{- end -}}


[BRCD_FABRIC_EXAMPLE]

#
# From cinder
#

# South bound connector for the fabric. (string value)
# Allowed values: SSH, HTTP, HTTPS
# from .brcd_fabric_example.cinder.fc_southbound_protocol
{{ if not .brcd_fabric_example.cinder.fc_southbound_protocol }}#{{ end }}fc_southbound_protocol = {{ .brcd_fabric_example.cinder.fc_southbound_protocol | default "HTTP" }}

# Management IP of fabric. (string value)
# from .brcd_fabric_example.cinder.fc_fabric_address
{{ if not .brcd_fabric_example.cinder.fc_fabric_address }}#{{ end }}fc_fabric_address = {{ .brcd_fabric_example.cinder.fc_fabric_address | default "" }}

# Fabric user ID. (string value)
# from .brcd_fabric_example.cinder.fc_fabric_user
{{ if not .brcd_fabric_example.cinder.fc_fabric_user }}#{{ end }}fc_fabric_user = {{ .brcd_fabric_example.cinder.fc_fabric_user | default "" }}

# Password for user. (string value)
# from .brcd_fabric_example.cinder.fc_fabric_password
{{ if not .brcd_fabric_example.cinder.fc_fabric_password }}#{{ end }}fc_fabric_password = {{ .brcd_fabric_example.cinder.fc_fabric_password | default "" }}

# Connecting port (port value)
# Minimum value: 0
# Maximum value: 65535
# from .brcd_fabric_example.cinder.fc_fabric_port
{{ if not .brcd_fabric_example.cinder.fc_fabric_port }}#{{ end }}fc_fabric_port = {{ .brcd_fabric_example.cinder.fc_fabric_port | default "22" }}

# Local SSH certificate Path. (string value)
# from .brcd_fabric_example.cinder.fc_fabric_ssh_cert_path
{{ if not .brcd_fabric_example.cinder.fc_fabric_ssh_cert_path }}#{{ end }}fc_fabric_ssh_cert_path = {{ .brcd_fabric_example.cinder.fc_fabric_ssh_cert_path | default "" }}

# Overridden zoning policy. (string value)
# from .brcd_fabric_example.cinder.zoning_policy
{{ if not .brcd_fabric_example.cinder.zoning_policy }}#{{ end }}zoning_policy = {{ .brcd_fabric_example.cinder.zoning_policy | default "initiator-target" }}

# Overridden zoning activation state. (boolean value)
# from .brcd_fabric_example.cinder.zone_activate
{{ if not .brcd_fabric_example.cinder.zone_activate }}#{{ end }}zone_activate = {{ .brcd_fabric_example.cinder.zone_activate | default "true" }}

# Overridden zone name prefix. (string value)
# from .brcd_fabric_example.cinder.zone_name_prefix
{{ if not .brcd_fabric_example.cinder.zone_name_prefix }}#{{ end }}zone_name_prefix = {{ .brcd_fabric_example.cinder.zone_name_prefix | default "openstack" }}

# Virtual Fabric ID. (string value)
# from .brcd_fabric_example.cinder.fc_virtual_fabric_id
{{ if not .brcd_fabric_example.cinder.fc_virtual_fabric_id }}#{{ end }}fc_virtual_fabric_id = {{ .brcd_fabric_example.cinder.fc_virtual_fabric_id | default "<None>" }}

# DEPRECATED: Principal switch WWN of the fabric. This option is not
# used anymore. (string value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# from .brcd_fabric_example.cinder.principal_switch_wwn
{{ if not .brcd_fabric_example.cinder.principal_switch_wwn }}#{{ end }}principal_switch_wwn = {{ .brcd_fabric_example.cinder.principal_switch_wwn | default "<None>" }}


[CISCO_FABRIC_EXAMPLE]

#
# From cinder
#

# Management IP of fabric (string value)
# from .cisco_fabric_example.cinder.cisco_fc_fabric_address
{{ if not .cisco_fabric_example.cinder.cisco_fc_fabric_address }}#{{ end }}cisco_fc_fabric_address = {{ .cisco_fabric_example.cinder.cisco_fc_fabric_address | default "" }}

# Fabric user ID (string value)
# from .cisco_fabric_example.cinder.cisco_fc_fabric_user
{{ if not .cisco_fabric_example.cinder.cisco_fc_fabric_user }}#{{ end }}cisco_fc_fabric_user = {{ .cisco_fabric_example.cinder.cisco_fc_fabric_user | default "" }}

# Password for user (string value)
# from .cisco_fabric_example.cinder.cisco_fc_fabric_password
{{ if not .cisco_fabric_example.cinder.cisco_fc_fabric_password }}#{{ end }}cisco_fc_fabric_password = {{ .cisco_fabric_example.cinder.cisco_fc_fabric_password | default "" }}

# Connecting port (port value)
# Minimum value: 0
# Maximum value: 65535
# from .cisco_fabric_example.cinder.cisco_fc_fabric_port
{{ if not .cisco_fabric_example.cinder.cisco_fc_fabric_port }}#{{ end }}cisco_fc_fabric_port = {{ .cisco_fabric_example.cinder.cisco_fc_fabric_port | default "22" }}

# overridden zoning policy (string value)
# from .cisco_fabric_example.cinder.cisco_zoning_policy
{{ if not .cisco_fabric_example.cinder.cisco_zoning_policy }}#{{ end }}cisco_zoning_policy = {{ .cisco_fabric_example.cinder.cisco_zoning_policy | default "initiator-target" }}

# overridden zoning activation state (boolean value)
# from .cisco_fabric_example.cinder.cisco_zone_activate
{{ if not .cisco_fabric_example.cinder.cisco_zone_activate }}#{{ end }}cisco_zone_activate = {{ .cisco_fabric_example.cinder.cisco_zone_activate | default "true" }}

# overridden zone name prefix (string value)
# from .cisco_fabric_example.cinder.cisco_zone_name_prefix
{{ if not .cisco_fabric_example.cinder.cisco_zone_name_prefix }}#{{ end }}cisco_zone_name_prefix = {{ .cisco_fabric_example.cinder.cisco_zone_name_prefix | default "<None>" }}

# VSAN of the Fabric (string value)
# from .cisco_fabric_example.cinder.cisco_zoning_vsan
{{ if not .cisco_fabric_example.cinder.cisco_zoning_vsan }}#{{ end }}cisco_zoning_vsan = {{ .cisco_fabric_example.cinder.cisco_zoning_vsan | default "<None>" }}


[COORDINATION]

#
# From cinder
#

# The backend URL to use for distributed coordination. (string value)
# from .coordination.cinder.backend_url
{{ if not .coordination.cinder.backend_url }}#{{ end }}backend_url = {{ .coordination.cinder.backend_url | default "file://$state_path" }}

# Number of seconds between heartbeats for distributed coordination.
# (floating point value)
# from .coordination.cinder.heartbeat
{{ if not .coordination.cinder.heartbeat }}#{{ end }}heartbeat = {{ .coordination.cinder.heartbeat | default "1.0" }}

# Initial number of seconds to wait after failed reconnection.
# (floating point value)
# from .coordination.cinder.initial_reconnect_backoff
{{ if not .coordination.cinder.initial_reconnect_backoff }}#{{ end }}initial_reconnect_backoff = {{ .coordination.cinder.initial_reconnect_backoff | default "0.1" }}

# Maximum number of seconds between sequential reconnection retries.
# (floating point value)
# from .coordination.cinder.max_reconnect_backoff
{{ if not .coordination.cinder.max_reconnect_backoff }}#{{ end }}max_reconnect_backoff = {{ .coordination.cinder.max_reconnect_backoff | default "60.0" }}


[FC-ZONE-MANAGER]

#
# From cinder
#

# South bound connector for zoning operation (string value)
# from .fc_zone_manager.cinder.brcd_sb_connector
{{ if not .fc_zone_manager.cinder.brcd_sb_connector }}#{{ end }}brcd_sb_connector = {{ .fc_zone_manager.cinder.brcd_sb_connector | default "HTTP" }}

# FC Zone Driver responsible for zone management (string value)
# from .fc_zone_manager.cinder.zone_driver
{{ if not .fc_zone_manager.cinder.zone_driver }}#{{ end }}zone_driver = {{ .fc_zone_manager.cinder.zone_driver | default "cinder.zonemanager.drivers.brocade.brcd_fc_zone_driver.BrcdFCZoneDriver" }}

# Zoning policy configured by user; valid values include "initiator-
# target" or "initiator" (string value)
# from .fc_zone_manager.cinder.zoning_policy
{{ if not .fc_zone_manager.cinder.zoning_policy }}#{{ end }}zoning_policy = {{ .fc_zone_manager.cinder.zoning_policy | default "initiator-target" }}

# Comma separated list of Fibre Channel fabric names. This list of
# names is used to retrieve other SAN credentials for connecting to
# each SAN fabric (string value)
# from .fc_zone_manager.cinder.fc_fabric_names
{{ if not .fc_zone_manager.cinder.fc_fabric_names }}#{{ end }}fc_fabric_names = {{ .fc_zone_manager.cinder.fc_fabric_names | default "<None>" }}

# FC SAN Lookup Service (string value)
# from .fc_zone_manager.cinder.fc_san_lookup_service
{{ if not .fc_zone_manager.cinder.fc_san_lookup_service }}#{{ end }}fc_san_lookup_service = {{ .fc_zone_manager.cinder.fc_san_lookup_service | default "cinder.zonemanager.drivers.brocade.brcd_fc_san_lookup_service.BrcdFCSanLookupService" }}

# Set this to True when you want to allow an unsupported zone manager
# driver to start.  Drivers that haven't maintained a working CI
# system and testing are marked as unsupported until CI is working
# again.  This also marks a driver as deprecated and may be removed in
# the next release. (boolean value)
# from .fc_zone_manager.cinder.enable_unsupported_driver
{{ if not .fc_zone_manager.cinder.enable_unsupported_driver }}#{{ end }}enable_unsupported_driver = {{ .fc_zone_manager.cinder.enable_unsupported_driver | default "false" }}

# Southbound connector for zoning operation (string value)
# from .fc_zone_manager.cinder.cisco_sb_connector
{{ if not .fc_zone_manager.cinder.cisco_sb_connector }}#{{ end }}cisco_sb_connector = {{ .fc_zone_manager.cinder.cisco_sb_connector | default "cinder.zonemanager.drivers.cisco.cisco_fc_zone_client_cli.CiscoFCZoneClientCLI" }}


[KEY_MANAGER]

#
# From cinder
#

# Fixed key returned by key manager, specified in hex (string value)
# Deprecated group/name - [keymgr]/fixed_key
# from .key_manager.cinder.fixed_key
{{ if not .key_manager.cinder.fixed_key }}#{{ end }}fixed_key = {{ .key_manager.cinder.fixed_key | default "<None>" }}


[barbican]

#
# From castellan.config
#

# Use this endpoint to connect to Barbican, for example:
# "http://localhost:9311/" (string value)
# from .barbican.castellan.config.barbican_endpoint
{{ if not .barbican.castellan.config.barbican_endpoint }}#{{ end }}barbican_endpoint = {{ .barbican.castellan.config.barbican_endpoint | default "<None>" }}

# Version of the Barbican API, for example: "v1" (string value)
# from .barbican.castellan.config.barbican_api_version
{{ if not .barbican.castellan.config.barbican_api_version }}#{{ end }}barbican_api_version = {{ .barbican.castellan.config.barbican_api_version | default "<None>" }}

# Use this endpoint to connect to Keystone (string value)
# from .barbican.castellan.config.auth_endpoint
{{ if not .barbican.castellan.config.auth_endpoint }}#{{ end }}auth_endpoint = {{ .barbican.castellan.config.auth_endpoint | default "http://localhost:5000/v3" }}

# Number of seconds to wait before retrying poll for key creation
# completion (integer value)
# from .barbican.castellan.config.retry_delay
{{ if not .barbican.castellan.config.retry_delay }}#{{ end }}retry_delay = {{ .barbican.castellan.config.retry_delay | default "1" }}

# Number of times to retry poll for key creation completion (integer
# value)
# from .barbican.castellan.config.number_of_retries
{{ if not .barbican.castellan.config.number_of_retries }}#{{ end }}number_of_retries = {{ .barbican.castellan.config.number_of_retries | default "60" }}


[cors]

#
# From oslo.middleware
#

# Indicate whether this resource may be shared with the domain
# received in the requests "origin" header. Format:
# "<protocol>://<host>[:<port>]", no trailing slash. Example:
# https://horizon.example.com (list value)
# from .cors.oslo.middleware.allowed_origin
{{ if not .cors.oslo.middleware.allowed_origin }}#{{ end }}allowed_origin = {{ .cors.oslo.middleware.allowed_origin | default "<None>" }}

# Indicate that the actual request can include user credentials
# (boolean value)
# from .cors.oslo.middleware.allow_credentials
{{ if not .cors.oslo.middleware.allow_credentials }}#{{ end }}allow_credentials = {{ .cors.oslo.middleware.allow_credentials | default "true" }}

# Indicate which headers are safe to expose to the API. Defaults to
# HTTP Simple Headers. (list value)
# from .cors.oslo.middleware.expose_headers
{{ if not .cors.oslo.middleware.expose_headers }}#{{ end }}expose_headers = {{ .cors.oslo.middleware.expose_headers | default "X-Auth-Token,X-Subject-Token,X-Service-Token,X-OpenStack-Request-ID,OpenStack-API-Version" }}

# Maximum cache age of CORS preflight requests. (integer value)
# from .cors.oslo.middleware.max_age
{{ if not .cors.oslo.middleware.max_age }}#{{ end }}max_age = {{ .cors.oslo.middleware.max_age | default "3600" }}

# Indicate which methods can be used during the actual request. (list
# value)
# from .cors.oslo.middleware.allow_methods
{{ if not .cors.oslo.middleware.allow_methods }}#{{ end }}allow_methods = {{ .cors.oslo.middleware.allow_methods | default "GET,PUT,POST,DELETE,PATCH,HEAD" }}

# Indicate which header field names may be used during the actual
# request. (list value)
# from .cors.oslo.middleware.allow_headers
{{ if not .cors.oslo.middleware.allow_headers }}#{{ end }}allow_headers = {{ .cors.oslo.middleware.allow_headers | default "X-Auth-Token,X-Identity-Status,X-Roles,X-Service-Catalog,X-User-Id,X-Tenant-Id,X-OpenStack-Request-ID,X-Trace-Info,X-Trace-HMAC,OpenStack-API-Version" }}


[cors.subdomain]

#
# From oslo.middleware
#

# Indicate whether this resource may be shared with the domain
# received in the requests "origin" header. Format:
# "<protocol>://<host>[:<port>]", no trailing slash. Example:
# https://horizon.example.com (list value)
# from .cors.subdomain.oslo.middleware.allowed_origin
{{ if not .cors.subdomain.oslo.middleware.allowed_origin }}#{{ end }}allowed_origin = {{ .cors.subdomain.oslo.middleware.allowed_origin | default "<None>" }}

# Indicate that the actual request can include user credentials
# (boolean value)
# from .cors.subdomain.oslo.middleware.allow_credentials
{{ if not .cors.subdomain.oslo.middleware.allow_credentials }}#{{ end }}allow_credentials = {{ .cors.subdomain.oslo.middleware.allow_credentials | default "true" }}

# Indicate which headers are safe to expose to the API. Defaults to
# HTTP Simple Headers. (list value)
# from .cors.subdomain.oslo.middleware.expose_headers
{{ if not .cors.subdomain.oslo.middleware.expose_headers }}#{{ end }}expose_headers = {{ .cors.subdomain.oslo.middleware.expose_headers | default "X-Auth-Token,X-Subject-Token,X-Service-Token,X-OpenStack-Request-ID,OpenStack-API-Version" }}

# Maximum cache age of CORS preflight requests. (integer value)
# from .cors.subdomain.oslo.middleware.max_age
{{ if not .cors.subdomain.oslo.middleware.max_age }}#{{ end }}max_age = {{ .cors.subdomain.oslo.middleware.max_age | default "3600" }}

# Indicate which methods can be used during the actual request. (list
# value)
# from .cors.subdomain.oslo.middleware.allow_methods
{{ if not .cors.subdomain.oslo.middleware.allow_methods }}#{{ end }}allow_methods = {{ .cors.subdomain.oslo.middleware.allow_methods | default "GET,PUT,POST,DELETE,PATCH,HEAD" }}

# Indicate which header field names may be used during the actual
# request. (list value)
# from .cors.subdomain.oslo.middleware.allow_headers
{{ if not .cors.subdomain.oslo.middleware.allow_headers }}#{{ end }}allow_headers = {{ .cors.subdomain.oslo.middleware.allow_headers | default "X-Auth-Token,X-Identity-Status,X-Roles,X-Service-Catalog,X-User-Id,X-Tenant-Id,X-OpenStack-Request-ID,X-Trace-Info,X-Trace-HMAC,OpenStack-API-Version" }}


[database]

#
# From oslo.db
#

# DEPRECATED: The file name to use with SQLite. (string value)
# Deprecated group/name - [DEFAULT]/sqlite_db
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Should use config option connection or slave_connection to
# connect the database.
# from .database.oslo.db.sqlite_db
{{ if not .database.oslo.db.sqlite_db }}#{{ end }}sqlite_db = {{ .database.oslo.db.sqlite_db | default "oslo.sqlite" }}

# If True, SQLite uses synchronous mode. (boolean value)
# Deprecated group/name - [DEFAULT]/sqlite_synchronous
# from .database.oslo.db.sqlite_synchronous
{{ if not .database.oslo.db.sqlite_synchronous }}#{{ end }}sqlite_synchronous = {{ .database.oslo.db.sqlite_synchronous | default "true" }}

# The back end to use for the database. (string value)
# Deprecated group/name - [DEFAULT]/db_backend
# from .database.oslo.db.backend
{{ if not .database.oslo.db.backend }}#{{ end }}backend = {{ .database.oslo.db.backend | default "sqlalchemy" }}

# The SQLAlchemy connection string to use to connect to the database.
# (string value)
# Deprecated group/name - [DEFAULT]/sql_connection
# Deprecated group/name - [DATABASE]/sql_connection
# Deprecated group/name - [sql]/connection
# from .database.oslo.db.connection
{{ if not .database.oslo.db.connection }}#{{ end }}connection = {{ .database.oslo.db.connection | default "<None>" }}

# The SQLAlchemy connection string to use to connect to the slave
# database. (string value)
# from .database.oslo.db.slave_connection
{{ if not .database.oslo.db.slave_connection }}#{{ end }}slave_connection = {{ .database.oslo.db.slave_connection | default "<None>" }}

# The SQL mode to be used for MySQL sessions. This option, including
# the default, overrides any server-set SQL mode. To use whatever SQL
# mode is set by the server configuration, set this to no value.
# Example: mysql_sql_mode= (string value)
# from .database.oslo.db.mysql_sql_mode
{{ if not .database.oslo.db.mysql_sql_mode }}#{{ end }}mysql_sql_mode = {{ .database.oslo.db.mysql_sql_mode | default "TRADITIONAL" }}

# Timeout before idle SQL connections are reaped. (integer value)
# Deprecated group/name - [DEFAULT]/sql_idle_timeout
# Deprecated group/name - [DATABASE]/sql_idle_timeout
# Deprecated group/name - [sql]/idle_timeout
# from .database.oslo.db.idle_timeout
{{ if not .database.oslo.db.idle_timeout }}#{{ end }}idle_timeout = {{ .database.oslo.db.idle_timeout | default "3600" }}

# Minimum number of SQL connections to keep open in a pool. (integer
# value)
# Deprecated group/name - [DEFAULT]/sql_min_pool_size
# Deprecated group/name - [DATABASE]/sql_min_pool_size
# from .database.oslo.db.min_pool_size
{{ if not .database.oslo.db.min_pool_size }}#{{ end }}min_pool_size = {{ .database.oslo.db.min_pool_size | default "1" }}

# Maximum number of SQL connections to keep open in a pool. Setting a
# value of 0 indicates no limit. (integer value)
# Deprecated group/name - [DEFAULT]/sql_max_pool_size
# Deprecated group/name - [DATABASE]/sql_max_pool_size
# from .database.oslo.db.max_pool_size
{{ if not .database.oslo.db.max_pool_size }}#{{ end }}max_pool_size = {{ .database.oslo.db.max_pool_size | default "5" }}

# Maximum number of database connection retries during startup. Set to
# -1 to specify an infinite retry count. (integer value)
# Deprecated group/name - [DEFAULT]/sql_max_retries
# Deprecated group/name - [DATABASE]/sql_max_retries
# from .database.oslo.db.max_retries
{{ if not .database.oslo.db.max_retries }}#{{ end }}max_retries = {{ .database.oslo.db.max_retries | default "10" }}

# Interval between retries of opening a SQL connection. (integer
# value)
# Deprecated group/name - [DEFAULT]/sql_retry_interval
# Deprecated group/name - [DATABASE]/reconnect_interval
# from .database.oslo.db.retry_interval
{{ if not .database.oslo.db.retry_interval }}#{{ end }}retry_interval = {{ .database.oslo.db.retry_interval | default "10" }}

# If set, use this value for max_overflow with SQLAlchemy. (integer
# value)
# Deprecated group/name - [DEFAULT]/sql_max_overflow
# Deprecated group/name - [DATABASE]/sqlalchemy_max_overflow
# from .database.oslo.db.max_overflow
{{ if not .database.oslo.db.max_overflow }}#{{ end }}max_overflow = {{ .database.oslo.db.max_overflow | default "50" }}

# Verbosity of SQL debugging information: 0=None, 100=Everything.
# (integer value)
# Minimum value: 0
# Maximum value: 100
# Deprecated group/name - [DEFAULT]/sql_connection_debug
# from .database.oslo.db.connection_debug
{{ if not .database.oslo.db.connection_debug }}#{{ end }}connection_debug = {{ .database.oslo.db.connection_debug | default "0" }}

# Add Python stack traces to SQL as comment strings. (boolean value)
# Deprecated group/name - [DEFAULT]/sql_connection_trace
# from .database.oslo.db.connection_trace
{{ if not .database.oslo.db.connection_trace }}#{{ end }}connection_trace = {{ .database.oslo.db.connection_trace | default "false" }}

# If set, use this value for pool_timeout with SQLAlchemy. (integer
# value)
# Deprecated group/name - [DATABASE]/sqlalchemy_pool_timeout
# from .database.oslo.db.pool_timeout
{{ if not .database.oslo.db.pool_timeout }}#{{ end }}pool_timeout = {{ .database.oslo.db.pool_timeout | default "<None>" }}

# Enable the experimental use of database reconnect on connection
# lost. (boolean value)
# from .database.oslo.db.use_db_reconnect
{{ if not .database.oslo.db.use_db_reconnect }}#{{ end }}use_db_reconnect = {{ .database.oslo.db.use_db_reconnect | default "false" }}

# Seconds between retries of a database transaction. (integer value)
# from .database.oslo.db.db_retry_interval
{{ if not .database.oslo.db.db_retry_interval }}#{{ end }}db_retry_interval = {{ .database.oslo.db.db_retry_interval | default "1" }}

# If True, increases the interval between retries of a database
# operation up to db_max_retry_interval. (boolean value)
# from .database.oslo.db.db_inc_retry_interval
{{ if not .database.oslo.db.db_inc_retry_interval }}#{{ end }}db_inc_retry_interval = {{ .database.oslo.db.db_inc_retry_interval | default "true" }}

# If db_inc_retry_interval is set, the maximum seconds between retries
# of a database operation. (integer value)
# from .database.oslo.db.db_max_retry_interval
{{ if not .database.oslo.db.db_max_retry_interval }}#{{ end }}db_max_retry_interval = {{ .database.oslo.db.db_max_retry_interval | default "10" }}

# Maximum retries in case of connection error or deadlock error before
# error is raised. Set to -1 to specify an infinite retry count.
# (integer value)
# from .database.oslo.db.db_max_retries
{{ if not .database.oslo.db.db_max_retries }}#{{ end }}db_max_retries = {{ .database.oslo.db.db_max_retries | default "20" }}


[key_manager]

#
# From castellan.config
#

# The full class name of the key manager API class (string value)
# from .key_manager.castellan.config.api_class
{{ if not .key_manager.castellan.config.api_class }}#{{ end }}api_class = {{ .key_manager.castellan.config.api_class | default "castellan.key_manager.barbican_key_manager.BarbicanKeyManager" }}

# The type of authentication credential to create. Possible values are
# 'token', 'password', 'keystone_token', and 'keystone_password'.
# Required if no context is passed to the credential factory. (string
# value)
# from .key_manager.castellan.config.auth_type
{{ if not .key_manager.castellan.config.auth_type }}#{{ end }}auth_type = {{ .key_manager.castellan.config.auth_type | default "<None>" }}

# Token for authentication. Required for 'token' and 'keystone_token'
# auth_type if no context is passed to the credential factory. (string
# value)
# from .key_manager.castellan.config.token
{{ if not .key_manager.castellan.config.token }}#{{ end }}token = {{ .key_manager.castellan.config.token | default "<None>" }}

# Username for authentication. Required for 'password' auth_type.
# Optional for the 'keystone_password' auth_type. (string value)
# from .key_manager.castellan.config.username
{{ if not .key_manager.castellan.config.username }}#{{ end }}username = {{ .key_manager.castellan.config.username | default "<None>" }}

# Password for authentication. Required for 'password' and
# 'keystone_password' auth_type. (string value)
# from .key_manager.castellan.config.password
{{ if not .key_manager.castellan.config.password }}#{{ end }}password = {{ .key_manager.castellan.config.password | default "<None>" }}

# User ID for authentication. Optional for 'keystone_token' and
# 'keystone_password' auth_type. (string value)
# from .key_manager.castellan.config.user_id
{{ if not .key_manager.castellan.config.user_id }}#{{ end }}user_id = {{ .key_manager.castellan.config.user_id | default "<None>" }}

# User's domain ID for authentication. Optional for 'keystone_token'
# and 'keystone_password' auth_type. (string value)
# from .key_manager.castellan.config.user_domain_id
{{ if not .key_manager.castellan.config.user_domain_id }}#{{ end }}user_domain_id = {{ .key_manager.castellan.config.user_domain_id | default "<None>" }}

# User's domain name for authentication. Optional for 'keystone_token'
# and 'keystone_password' auth_type. (string value)
# from .key_manager.castellan.config.user_domain_name
{{ if not .key_manager.castellan.config.user_domain_name }}#{{ end }}user_domain_name = {{ .key_manager.castellan.config.user_domain_name | default "<None>" }}

# Trust ID for trust scoping. Optional for 'keystone_token' and
# 'keystone_password' auth_type. (string value)
# from .key_manager.castellan.config.trust_id
{{ if not .key_manager.castellan.config.trust_id }}#{{ end }}trust_id = {{ .key_manager.castellan.config.trust_id | default "<None>" }}

# Domain ID for domain scoping. Optional for 'keystone_token' and
# 'keystone_password' auth_type. (string value)
# from .key_manager.castellan.config.domain_id
{{ if not .key_manager.castellan.config.domain_id }}#{{ end }}domain_id = {{ .key_manager.castellan.config.domain_id | default "<None>" }}

# Domain name for domain scoping. Optional for 'keystone_token' and
# 'keystone_password' auth_type. (string value)
# from .key_manager.castellan.config.domain_name
{{ if not .key_manager.castellan.config.domain_name }}#{{ end }}domain_name = {{ .key_manager.castellan.config.domain_name | default "<None>" }}

# Project ID for project scoping. Optional for 'keystone_token' and
# 'keystone_password' auth_type. (string value)
# from .key_manager.castellan.config.project_id
{{ if not .key_manager.castellan.config.project_id }}#{{ end }}project_id = {{ .key_manager.castellan.config.project_id | default "<None>" }}

# Project name for project scoping. Optional for 'keystone_token' and
# 'keystone_password' auth_type. (string value)
# from .key_manager.castellan.config.project_name
{{ if not .key_manager.castellan.config.project_name }}#{{ end }}project_name = {{ .key_manager.castellan.config.project_name | default "<None>" }}

# Project's domain ID for project. Optional for 'keystone_token' and
# 'keystone_password' auth_type. (string value)
# from .key_manager.castellan.config.project_domain_id
{{ if not .key_manager.castellan.config.project_domain_id }}#{{ end }}project_domain_id = {{ .key_manager.castellan.config.project_domain_id | default "<None>" }}

# Project's domain name for project. Optional for 'keystone_token' and
# 'keystone_password' auth_type. (string value)
# from .key_manager.castellan.config.project_domain_name
{{ if not .key_manager.castellan.config.project_domain_name }}#{{ end }}project_domain_name = {{ .key_manager.castellan.config.project_domain_name | default "<None>" }}

# Allow fetching a new token if the current one is going to expire.
# Optional for 'keystone_token' and 'keystone_password' auth_type.
# (boolean value)
# from .key_manager.castellan.config.reauthenticate
{{ if not .key_manager.castellan.config.reauthenticate }}#{{ end }}reauthenticate = {{ .key_manager.castellan.config.reauthenticate | default "true" }}


[keystone_authtoken]

#
# From keystonemiddleware.auth_token
#

# FIXME(dulek) - added the next several lines because oslo gen config refuses to generate the line items required in keystonemiddleware
# for authentication - while it does support an "auth_section" parameter to locate these elsewhere, it would be a strange divergence
# from how neutron keystone authentication is stored today - ocata and later appear to use a "service" user section which can house these details
# and does successfully generate beyond newton, so likely this whole section will be removed the next time we generate this file

{{ if not .keystone_authtoken.keystonemiddleware.auth_token.auth_url }}#{{ end }}auth_url = {{ .keystone_authtoken.keystonemiddleware.auth_token.auth_url | default "<None>" }}
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.region_name }}#{{ end }}region_name = {{ .keystone_authtoken.keystonemiddleware.auth_token.region_name | default "<None>" }}
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.project_name }}#{{ end }}project_name = {{ .keystone_authtoken.keystonemiddleware.auth_token.project_name | default "<None>" }}
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.project_domain_name }}#{{ end }}project_domain_name = {{ .keystone_authtoken.keystonemiddleware.auth_token.project_domain_name | default "<None>" }}
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.user_domain_name }}#{{ end }}user_domain_name = {{ .keystone_authtoken.keystonemiddleware.auth_token.user_domain_name | default "<None>" }}
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.username }}#{{ end }}username = {{ .keystone_authtoken.keystonemiddleware.auth_token.username | default "<None>" }}
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.password }}#{{ end }}password = {{ .keystone_authtoken.keystonemiddleware.auth_token.password | default "<None>" }}

# Complete "public" Identity API endpoint. This endpoint should not be
# an "admin" endpoint, as it should be accessible by all end users.
# Unauthenticated clients are redirected to this endpoint to
# authenticate. Although this endpoint should  ideally be unversioned,
# client support in the wild varies.  If you're using a versioned v2
# endpoint here, then this  should *not* be the same endpoint the
# service user utilizes  for validating tokens, because normal end
# users may not be  able to reach that endpoint. (string value)
# from .keystone_authtoken.keystonemiddleware.auth_token.auth_uri
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.auth_uri }}#{{ end }}auth_uri = {{ .keystone_authtoken.keystonemiddleware.auth_token.auth_uri | default "<None>" }}

# API version of the admin Identity API endpoint. (string value)
# from .keystone_authtoken.keystonemiddleware.auth_token.auth_version
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.auth_version }}#{{ end }}auth_version = {{ .keystone_authtoken.keystonemiddleware.auth_token.auth_version | default "<None>" }}

# Do not handle authorization requests within the middleware, but
# delegate the authorization decision to downstream WSGI components.
# (boolean value)
# from .keystone_authtoken.keystonemiddleware.auth_token.delay_auth_decision
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.delay_auth_decision }}#{{ end }}delay_auth_decision = {{ .keystone_authtoken.keystonemiddleware.auth_token.delay_auth_decision | default "false" }}

# Request timeout value for communicating with Identity API server.
# (integer value)
# from .keystone_authtoken.keystonemiddleware.auth_token.http_connect_timeout
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.http_connect_timeout }}#{{ end }}http_connect_timeout = {{ .keystone_authtoken.keystonemiddleware.auth_token.http_connect_timeout | default "<None>" }}

# How many times are we trying to reconnect when communicating with
# Identity API Server. (integer value)
# from .keystone_authtoken.keystonemiddleware.auth_token.http_request_max_retries
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.http_request_max_retries }}#{{ end }}http_request_max_retries = {{ .keystone_authtoken.keystonemiddleware.auth_token.http_request_max_retries | default "3" }}

# Request environment key where the Swift cache object is stored. When
# auth_token middleware is deployed with a Swift cache, use this
# option to have the middleware share a caching backend with swift.
# Otherwise, use the ``memcached_servers`` option instead. (string
# value)
# from .keystone_authtoken.keystonemiddleware.auth_token.cache
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.cache }}#{{ end }}cache = {{ .keystone_authtoken.keystonemiddleware.auth_token.cache | default "<None>" }}

# Required if identity server requires client certificate (string
# value)
# from .keystone_authtoken.keystonemiddleware.auth_token.certfile
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.certfile }}#{{ end }}certfile = {{ .keystone_authtoken.keystonemiddleware.auth_token.certfile | default "<None>" }}

# Required if identity server requires client certificate (string
# value)
# from .keystone_authtoken.keystonemiddleware.auth_token.keyfile
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.keyfile }}#{{ end }}keyfile = {{ .keystone_authtoken.keystonemiddleware.auth_token.keyfile | default "<None>" }}

# A PEM encoded Certificate Authority to use when verifying HTTPs
# connections. Defaults to system CAs. (string value)
# from .keystone_authtoken.keystonemiddleware.auth_token.cafile
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.cafile }}#{{ end }}cafile = {{ .keystone_authtoken.keystonemiddleware.auth_token.cafile | default "<None>" }}

# Verify HTTPS connections. (boolean value)
# from .keystone_authtoken.keystonemiddleware.auth_token.insecure
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.insecure }}#{{ end }}insecure = {{ .keystone_authtoken.keystonemiddleware.auth_token.insecure | default "false" }}

# The region in which the identity server can be found. (string value)
# from .keystone_authtoken.keystonemiddleware.auth_token.region_name
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.region_name }}#{{ end }}region_name = {{ .keystone_authtoken.keystonemiddleware.auth_token.region_name | default "<None>" }}

# Directory used to cache files related to PKI tokens. (string value)
# from .keystone_authtoken.keystonemiddleware.auth_token.signing_dir
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.signing_dir }}#{{ end }}signing_dir = {{ .keystone_authtoken.keystonemiddleware.auth_token.signing_dir | default "<None>" }}

# Optionally specify a list of memcached server(s) to use for caching.
# If left undefined, tokens will instead be cached in-process. (list
# value)
# Deprecated group/name - [keystone_authtoken]/memcache_servers
# from .keystone_authtoken.keystonemiddleware.auth_token.memcached_servers
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.memcached_servers }}#{{ end }}memcached_servers = {{ .keystone_authtoken.keystonemiddleware.auth_token.memcached_servers | default "<None>" }}

# In order to prevent excessive effort spent validating tokens, the
# middleware caches previously-seen tokens for a configurable duration
# (in seconds). Set to -1 to disable caching completely. (integer
# value)
# from .keystone_authtoken.keystonemiddleware.auth_token.token_cache_time
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.token_cache_time }}#{{ end }}token_cache_time = {{ .keystone_authtoken.keystonemiddleware.auth_token.token_cache_time | default "300" }}

# Determines the frequency at which the list of revoked tokens is
# retrieved from the Identity service (in seconds). A high number of
# revocation events combined with a low cache duration may
# significantly reduce performance. Only valid for PKI tokens.
# (integer value)
# from .keystone_authtoken.keystonemiddleware.auth_token.revocation_cache_time
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.revocation_cache_time }}#{{ end }}revocation_cache_time = {{ .keystone_authtoken.keystonemiddleware.auth_token.revocation_cache_time | default "10" }}

# (Optional) If defined, indicate whether token data should be
# authenticated or authenticated and encrypted. If MAC, token data is
# authenticated (with HMAC) in the cache. If ENCRYPT, token data is
# encrypted and authenticated in the cache. If the value is not one of
# these options or empty, auth_token will raise an exception on
# initialization. (string value)
# Allowed values: None, MAC, ENCRYPT
# from .keystone_authtoken.keystonemiddleware.auth_token.memcache_security_strategy
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.memcache_security_strategy }}#{{ end }}memcache_security_strategy = {{ .keystone_authtoken.keystonemiddleware.auth_token.memcache_security_strategy | default "None" }}

# (Optional, mandatory if memcache_security_strategy is defined) This
# string is used for key derivation. (string value)
# from .keystone_authtoken.keystonemiddleware.auth_token.memcache_secret_key
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.memcache_secret_key }}#{{ end }}memcache_secret_key = {{ .keystone_authtoken.keystonemiddleware.auth_token.memcache_secret_key | default "<None>" }}

# (Optional) Number of seconds memcached server is considered dead
# before it is tried again. (integer value)
# from .keystone_authtoken.keystonemiddleware.auth_token.memcache_pool_dead_retry
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.memcache_pool_dead_retry }}#{{ end }}memcache_pool_dead_retry = {{ .keystone_authtoken.keystonemiddleware.auth_token.memcache_pool_dead_retry | default "300" }}

# (Optional) Maximum total number of open connections to every
# memcached server. (integer value)
# from .keystone_authtoken.keystonemiddleware.auth_token.memcache_pool_maxsize
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.memcache_pool_maxsize }}#{{ end }}memcache_pool_maxsize = {{ .keystone_authtoken.keystonemiddleware.auth_token.memcache_pool_maxsize | default "10" }}

# (Optional) Socket timeout in seconds for communicating with a
# memcached server. (integer value)
# from .keystone_authtoken.keystonemiddleware.auth_token.memcache_pool_socket_timeout
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.memcache_pool_socket_timeout }}#{{ end }}memcache_pool_socket_timeout = {{ .keystone_authtoken.keystonemiddleware.auth_token.memcache_pool_socket_timeout | default "3" }}

# (Optional) Number of seconds a connection to memcached is held
# unused in the pool before it is closed. (integer value)
# from .keystone_authtoken.keystonemiddleware.auth_token.memcache_pool_unused_timeout
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.memcache_pool_unused_timeout }}#{{ end }}memcache_pool_unused_timeout = {{ .keystone_authtoken.keystonemiddleware.auth_token.memcache_pool_unused_timeout | default "60" }}

# (Optional) Number of seconds that an operation will wait to get a
# memcached client connection from the pool. (integer value)
# from .keystone_authtoken.keystonemiddleware.auth_token.memcache_pool_conn_get_timeout
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.memcache_pool_conn_get_timeout }}#{{ end }}memcache_pool_conn_get_timeout = {{ .keystone_authtoken.keystonemiddleware.auth_token.memcache_pool_conn_get_timeout | default "10" }}

# (Optional) Use the advanced (eventlet safe) memcached client pool.
# The advanced pool will only work under python 2.x. (boolean value)
# from .keystone_authtoken.keystonemiddleware.auth_token.memcache_use_advanced_pool
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.memcache_use_advanced_pool }}#{{ end }}memcache_use_advanced_pool = {{ .keystone_authtoken.keystonemiddleware.auth_token.memcache_use_advanced_pool | default "false" }}

# (Optional) Indicate whether to set the X-Service-Catalog header. If
# False, middleware will not ask for service catalog on token
# validation and will not set the X-Service-Catalog header. (boolean
# value)
# from .keystone_authtoken.keystonemiddleware.auth_token.include_service_catalog
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.include_service_catalog }}#{{ end }}include_service_catalog = {{ .keystone_authtoken.keystonemiddleware.auth_token.include_service_catalog | default "true" }}

# Used to control the use and type of token binding. Can be set to:
# "disabled" to not check token binding. "permissive" (default) to
# validate binding information if the bind type is of a form known to
# the server and ignore it if not. "strict" like "permissive" but if
# the bind type is unknown the token will be rejected. "required" any
# form of token binding is needed to be allowed. Finally the name of a
# binding method that must be present in tokens. (string value)
# from .keystone_authtoken.keystonemiddleware.auth_token.enforce_token_bind
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.enforce_token_bind }}#{{ end }}enforce_token_bind = {{ .keystone_authtoken.keystonemiddleware.auth_token.enforce_token_bind | default "permissive" }}

# If true, the revocation list will be checked for cached tokens. This
# requires that PKI tokens are configured on the identity server.
# (boolean value)
# from .keystone_authtoken.keystonemiddleware.auth_token.check_revocations_for_cached
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.check_revocations_for_cached }}#{{ end }}check_revocations_for_cached = {{ .keystone_authtoken.keystonemiddleware.auth_token.check_revocations_for_cached | default "false" }}

# Hash algorithms to use for hashing PKI tokens. This may be a single
# algorithm or multiple. The algorithms are those supported by Python
# standard hashlib.new(). The hashes will be tried in the order given,
# so put the preferred one first for performance. The result of the
# first hash will be stored in the cache. This will typically be set
# to multiple values only while migrating from a less secure algorithm
# to a more secure one. Once all the old tokens are expired this
# option should be set to a single value for better performance. (list
# value)
# from .keystone_authtoken.keystonemiddleware.auth_token.hash_algorithms
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.hash_algorithms }}#{{ end }}hash_algorithms = {{ .keystone_authtoken.keystonemiddleware.auth_token.hash_algorithms | default "md5" }}

# Authentication type to load (string value)
# Deprecated group/name - [keystone_authtoken]/auth_plugin
# from .keystone_authtoken.keystonemiddleware.auth_token.auth_type
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.auth_type }}#{{ end }}auth_type = {{ .keystone_authtoken.keystonemiddleware.auth_token.auth_type | default "<None>" }}

# Config Section from which to load plugin specific options (string
# value)
# from .keystone_authtoken.keystonemiddleware.auth_token.auth_section
{{ if not .keystone_authtoken.keystonemiddleware.auth_token.auth_section }}#{{ end }}auth_section = {{ .keystone_authtoken.keystonemiddleware.auth_token.auth_section | default "<None>" }}


[matchmaker_redis]

#
# From oslo.messaging
#

# DEPRECATED: Host to locate redis. (string value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .matchmaker_redis.oslo.messaging.host
{{ if not .matchmaker_redis.oslo.messaging.host }}#{{ end }}host = {{ .matchmaker_redis.oslo.messaging.host | default "127.0.0.1" }}

# DEPRECATED: Use this port to connect to redis host. (port value)
# Minimum value: 0
# Maximum value: 65535
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .matchmaker_redis.oslo.messaging.port
{{ if not .matchmaker_redis.oslo.messaging.port }}#{{ end }}port = {{ .matchmaker_redis.oslo.messaging.port | default "6379" }}

# DEPRECATED: Password for Redis server (optional). (string value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .matchmaker_redis.oslo.messaging.password
{{ if not .matchmaker_redis.oslo.messaging.password }}#{{ end }}password = {{ .matchmaker_redis.oslo.messaging.password | default "" }}

# DEPRECATED: List of Redis Sentinel hosts (fault tolerance mode) e.g.
# [host:port, host1:port ... ] (list value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .matchmaker_redis.oslo.messaging.sentinel_hosts
{{ if not .matchmaker_redis.oslo.messaging.sentinel_hosts }}#{{ end }}sentinel_hosts = {{ .matchmaker_redis.oslo.messaging.sentinel_hosts | default "" }}

# Redis replica set name. (string value)
# from .matchmaker_redis.oslo.messaging.sentinel_group_name
{{ if not .matchmaker_redis.oslo.messaging.sentinel_group_name }}#{{ end }}sentinel_group_name = {{ .matchmaker_redis.oslo.messaging.sentinel_group_name | default "oslo-messaging-zeromq" }}

# Time in ms to wait between connection attempts. (integer value)
# from .matchmaker_redis.oslo.messaging.wait_timeout
{{ if not .matchmaker_redis.oslo.messaging.wait_timeout }}#{{ end }}wait_timeout = {{ .matchmaker_redis.oslo.messaging.wait_timeout | default "2000" }}

# Time in ms to wait before the transaction is killed. (integer value)
# from .matchmaker_redis.oslo.messaging.check_timeout
{{ if not .matchmaker_redis.oslo.messaging.check_timeout }}#{{ end }}check_timeout = {{ .matchmaker_redis.oslo.messaging.check_timeout | default "20000" }}

# Timeout in ms on blocking socket operations (integer value)
# from .matchmaker_redis.oslo.messaging.socket_timeout
{{ if not .matchmaker_redis.oslo.messaging.socket_timeout }}#{{ end }}socket_timeout = {{ .matchmaker_redis.oslo.messaging.socket_timeout | default "10000" }}


[oslo_concurrency]

#
# From oslo.concurrency
#

# Enables or disables inter-process locks. (boolean value)
# Deprecated group/name - [DEFAULT]/disable_process_locking
# from .oslo_concurrency.oslo.concurrency.disable_process_locking
{{ if not .oslo_concurrency.oslo.concurrency.disable_process_locking }}#{{ end }}disable_process_locking = {{ .oslo_concurrency.oslo.concurrency.disable_process_locking | default "false" }}

# Directory to use for lock files.  For security, the specified
# directory should only be writable by the user running the processes
# that need locking. Defaults to environment variable OSLO_LOCK_PATH.
# If external locks are used, a lock path must be set. (string value)
# Deprecated group/name - [DEFAULT]/lock_path
# from .oslo_concurrency.oslo.concurrency.lock_path
{{ if not .oslo_concurrency.oslo.concurrency.lock_path }}#{{ end }}lock_path = {{ .oslo_concurrency.oslo.concurrency.lock_path | default "<None>" }}


[oslo_messaging_amqp]

#
# From oslo.messaging
#

# Name for the AMQP container. must be globally unique. Defaults to a
# generated UUID (string value)
# Deprecated group/name - [amqp1]/container_name
# from .oslo_messaging_amqp.oslo.messaging.container_name
{{ if not .oslo_messaging_amqp.oslo.messaging.container_name }}#{{ end }}container_name = {{ .oslo_messaging_amqp.oslo.messaging.container_name | default "<None>" }}

# Timeout for inactive connections (in seconds) (integer value)
# Deprecated group/name - [amqp1]/idle_timeout
# from .oslo_messaging_amqp.oslo.messaging.idle_timeout
{{ if not .oslo_messaging_amqp.oslo.messaging.idle_timeout }}#{{ end }}idle_timeout = {{ .oslo_messaging_amqp.oslo.messaging.idle_timeout | default "0" }}

# Debug: dump AMQP frames to stdout (boolean value)
# Deprecated group/name - [amqp1]/trace
# from .oslo_messaging_amqp.oslo.messaging.trace
{{ if not .oslo_messaging_amqp.oslo.messaging.trace }}#{{ end }}trace = {{ .oslo_messaging_amqp.oslo.messaging.trace | default "false" }}

# CA certificate PEM file to verify server certificate (string value)
# Deprecated group/name - [amqp1]/ssl_ca_file
# from .oslo_messaging_amqp.oslo.messaging.ssl_ca_file
{{ if not .oslo_messaging_amqp.oslo.messaging.ssl_ca_file }}#{{ end }}ssl_ca_file = {{ .oslo_messaging_amqp.oslo.messaging.ssl_ca_file | default "" }}

# Identifying certificate PEM file to present to clients (string
# value)
# Deprecated group/name - [amqp1]/ssl_cert_file
# from .oslo_messaging_amqp.oslo.messaging.ssl_cert_file
{{ if not .oslo_messaging_amqp.oslo.messaging.ssl_cert_file }}#{{ end }}ssl_cert_file = {{ .oslo_messaging_amqp.oslo.messaging.ssl_cert_file | default "" }}

# Private key PEM file used to sign cert_file certificate (string
# value)
# Deprecated group/name - [amqp1]/ssl_key_file
# from .oslo_messaging_amqp.oslo.messaging.ssl_key_file
{{ if not .oslo_messaging_amqp.oslo.messaging.ssl_key_file }}#{{ end }}ssl_key_file = {{ .oslo_messaging_amqp.oslo.messaging.ssl_key_file | default "" }}

# Password for decrypting ssl_key_file (if encrypted) (string value)
# Deprecated group/name - [amqp1]/ssl_key_password
# from .oslo_messaging_amqp.oslo.messaging.ssl_key_password
{{ if not .oslo_messaging_amqp.oslo.messaging.ssl_key_password }}#{{ end }}ssl_key_password = {{ .oslo_messaging_amqp.oslo.messaging.ssl_key_password | default "<None>" }}

# Accept clients using either SSL or plain TCP (boolean value)
# Deprecated group/name - [amqp1]/allow_insecure_clients
# from .oslo_messaging_amqp.oslo.messaging.allow_insecure_clients
{{ if not .oslo_messaging_amqp.oslo.messaging.allow_insecure_clients }}#{{ end }}allow_insecure_clients = {{ .oslo_messaging_amqp.oslo.messaging.allow_insecure_clients | default "false" }}

# Space separated list of acceptable SASL mechanisms (string value)
# Deprecated group/name - [amqp1]/sasl_mechanisms
# from .oslo_messaging_amqp.oslo.messaging.sasl_mechanisms
{{ if not .oslo_messaging_amqp.oslo.messaging.sasl_mechanisms }}#{{ end }}sasl_mechanisms = {{ .oslo_messaging_amqp.oslo.messaging.sasl_mechanisms | default "" }}

# Path to directory that contains the SASL configuration (string
# value)
# Deprecated group/name - [amqp1]/sasl_config_dir
# from .oslo_messaging_amqp.oslo.messaging.sasl_config_dir
{{ if not .oslo_messaging_amqp.oslo.messaging.sasl_config_dir }}#{{ end }}sasl_config_dir = {{ .oslo_messaging_amqp.oslo.messaging.sasl_config_dir | default "" }}

# Name of configuration file (without .conf suffix) (string value)
# Deprecated group/name - [amqp1]/sasl_config_name
# from .oslo_messaging_amqp.oslo.messaging.sasl_config_name
{{ if not .oslo_messaging_amqp.oslo.messaging.sasl_config_name }}#{{ end }}sasl_config_name = {{ .oslo_messaging_amqp.oslo.messaging.sasl_config_name | default "" }}

# User name for message broker authentication (string value)
# Deprecated group/name - [amqp1]/username
# from .oslo_messaging_amqp.oslo.messaging.username
{{ if not .oslo_messaging_amqp.oslo.messaging.username }}#{{ end }}username = {{ .oslo_messaging_amqp.oslo.messaging.username | default "" }}

# Password for message broker authentication (string value)
# Deprecated group/name - [amqp1]/password
# from .oslo_messaging_amqp.oslo.messaging.password
{{ if not .oslo_messaging_amqp.oslo.messaging.password }}#{{ end }}password = {{ .oslo_messaging_amqp.oslo.messaging.password | default "" }}

# Seconds to pause before attempting to re-connect. (integer value)
# Minimum value: 1
# from .oslo_messaging_amqp.oslo.messaging.connection_retry_interval
{{ if not .oslo_messaging_amqp.oslo.messaging.connection_retry_interval }}#{{ end }}connection_retry_interval = {{ .oslo_messaging_amqp.oslo.messaging.connection_retry_interval | default "1" }}

# Increase the connection_retry_interval by this many seconds after
# each unsuccessful failover attempt. (integer value)
# Minimum value: 0
# from .oslo_messaging_amqp.oslo.messaging.connection_retry_backoff
{{ if not .oslo_messaging_amqp.oslo.messaging.connection_retry_backoff }}#{{ end }}connection_retry_backoff = {{ .oslo_messaging_amqp.oslo.messaging.connection_retry_backoff | default "2" }}

# Maximum limit for connection_retry_interval +
# connection_retry_backoff (integer value)
# Minimum value: 1
# from .oslo_messaging_amqp.oslo.messaging.connection_retry_interval_max
{{ if not .oslo_messaging_amqp.oslo.messaging.connection_retry_interval_max }}#{{ end }}connection_retry_interval_max = {{ .oslo_messaging_amqp.oslo.messaging.connection_retry_interval_max | default "30" }}

# Time to pause between re-connecting an AMQP 1.0 link that failed due
# to a recoverable error. (integer value)
# Minimum value: 1
# from .oslo_messaging_amqp.oslo.messaging.link_retry_delay
{{ if not .oslo_messaging_amqp.oslo.messaging.link_retry_delay }}#{{ end }}link_retry_delay = {{ .oslo_messaging_amqp.oslo.messaging.link_retry_delay | default "10" }}

# The deadline for an rpc reply message delivery. Only used when
# caller does not provide a timeout expiry. (integer value)
# Minimum value: 5
# from .oslo_messaging_amqp.oslo.messaging.default_reply_timeout
{{ if not .oslo_messaging_amqp.oslo.messaging.default_reply_timeout }}#{{ end }}default_reply_timeout = {{ .oslo_messaging_amqp.oslo.messaging.default_reply_timeout | default "30" }}

# The deadline for an rpc cast or call message delivery. Only used
# when caller does not provide a timeout expiry. (integer value)
# Minimum value: 5
# from .oslo_messaging_amqp.oslo.messaging.default_send_timeout
{{ if not .oslo_messaging_amqp.oslo.messaging.default_send_timeout }}#{{ end }}default_send_timeout = {{ .oslo_messaging_amqp.oslo.messaging.default_send_timeout | default "30" }}

# The deadline for a sent notification message delivery. Only used
# when caller does not provide a timeout expiry. (integer value)
# Minimum value: 5
# from .oslo_messaging_amqp.oslo.messaging.default_notify_timeout
{{ if not .oslo_messaging_amqp.oslo.messaging.default_notify_timeout }}#{{ end }}default_notify_timeout = {{ .oslo_messaging_amqp.oslo.messaging.default_notify_timeout | default "30" }}

# Indicates the addressing mode used by the driver.
# Permitted values:
# 'legacy'   - use legacy non-routable addressing
# 'routable' - use routable addresses
# 'dynamic'  - use legacy addresses if the message bus does not
# support routing otherwise use routable addressing (string value)
# from .oslo_messaging_amqp.oslo.messaging.addressing_mode
{{ if not .oslo_messaging_amqp.oslo.messaging.addressing_mode }}#{{ end }}addressing_mode = {{ .oslo_messaging_amqp.oslo.messaging.addressing_mode | default "dynamic" }}

# address prefix used when sending to a specific server (string value)
# Deprecated group/name - [amqp1]/server_request_prefix
# from .oslo_messaging_amqp.oslo.messaging.server_request_prefix
{{ if not .oslo_messaging_amqp.oslo.messaging.server_request_prefix }}#{{ end }}server_request_prefix = {{ .oslo_messaging_amqp.oslo.messaging.server_request_prefix | default "exclusive" }}

# address prefix used when broadcasting to all servers (string value)
# Deprecated group/name - [amqp1]/broadcast_prefix
# from .oslo_messaging_amqp.oslo.messaging.broadcast_prefix
{{ if not .oslo_messaging_amqp.oslo.messaging.broadcast_prefix }}#{{ end }}broadcast_prefix = {{ .oslo_messaging_amqp.oslo.messaging.broadcast_prefix | default "broadcast" }}

# address prefix when sending to any server in group (string value)
# Deprecated group/name - [amqp1]/group_request_prefix
# from .oslo_messaging_amqp.oslo.messaging.group_request_prefix
{{ if not .oslo_messaging_amqp.oslo.messaging.group_request_prefix }}#{{ end }}group_request_prefix = {{ .oslo_messaging_amqp.oslo.messaging.group_request_prefix | default "unicast" }}

# Address prefix for all generated RPC addresses (string value)
# from .oslo_messaging_amqp.oslo.messaging.rpc_address_prefix
{{ if not .oslo_messaging_amqp.oslo.messaging.rpc_address_prefix }}#{{ end }}rpc_address_prefix = {{ .oslo_messaging_amqp.oslo.messaging.rpc_address_prefix | default "openstack.org/om/rpc" }}

# Address prefix for all generated Notification addresses (string
# value)
# from .oslo_messaging_amqp.oslo.messaging.notify_address_prefix
{{ if not .oslo_messaging_amqp.oslo.messaging.notify_address_prefix }}#{{ end }}notify_address_prefix = {{ .oslo_messaging_amqp.oslo.messaging.notify_address_prefix | default "openstack.org/om/notify" }}

# Appended to the address prefix when sending a fanout message. Used
# by the message bus to identify fanout messages. (string value)
# from .oslo_messaging_amqp.oslo.messaging.multicast_address
{{ if not .oslo_messaging_amqp.oslo.messaging.multicast_address }}#{{ end }}multicast_address = {{ .oslo_messaging_amqp.oslo.messaging.multicast_address | default "multicast" }}

# Appended to the address prefix when sending to a particular
# RPC/Notification server. Used by the message bus to identify
# messages sent to a single destination. (string value)
# from .oslo_messaging_amqp.oslo.messaging.unicast_address
{{ if not .oslo_messaging_amqp.oslo.messaging.unicast_address }}#{{ end }}unicast_address = {{ .oslo_messaging_amqp.oslo.messaging.unicast_address | default "unicast" }}

# Appended to the address prefix when sending to a group of consumers.
# Used by the message bus to identify messages that should be
# delivered in a round-robin fashion across consumers. (string value)
# from .oslo_messaging_amqp.oslo.messaging.anycast_address
{{ if not .oslo_messaging_amqp.oslo.messaging.anycast_address }}#{{ end }}anycast_address = {{ .oslo_messaging_amqp.oslo.messaging.anycast_address | default "anycast" }}

# Exchange name used in notification addresses.
# Exchange name resolution precedence:
# Target.exchange if set
# else default_notification_exchange if set
# else control_exchange if set
# else 'notify' (string value)
# from .oslo_messaging_amqp.oslo.messaging.default_notification_exchange
{{ if not .oslo_messaging_amqp.oslo.messaging.default_notification_exchange }}#{{ end }}default_notification_exchange = {{ .oslo_messaging_amqp.oslo.messaging.default_notification_exchange | default "<None>" }}

# Exchange name used in RPC addresses.
# Exchange name resolution precedence:
# Target.exchange if set
# else default_rpc_exchange if set
# else control_exchange if set
# else 'rpc' (string value)
# from .oslo_messaging_amqp.oslo.messaging.default_rpc_exchange
{{ if not .oslo_messaging_amqp.oslo.messaging.default_rpc_exchange }}#{{ end }}default_rpc_exchange = {{ .oslo_messaging_amqp.oslo.messaging.default_rpc_exchange | default "<None>" }}

# Window size for incoming RPC Reply messages. (integer value)
# Minimum value: 1
# from .oslo_messaging_amqp.oslo.messaging.reply_link_credit
{{ if not .oslo_messaging_amqp.oslo.messaging.reply_link_credit }}#{{ end }}reply_link_credit = {{ .oslo_messaging_amqp.oslo.messaging.reply_link_credit | default "200" }}

# Window size for incoming RPC Request messages (integer value)
# Minimum value: 1
# from .oslo_messaging_amqp.oslo.messaging.rpc_server_credit
{{ if not .oslo_messaging_amqp.oslo.messaging.rpc_server_credit }}#{{ end }}rpc_server_credit = {{ .oslo_messaging_amqp.oslo.messaging.rpc_server_credit | default "100" }}

# Window size for incoming Notification messages (integer value)
# Minimum value: 1
# from .oslo_messaging_amqp.oslo.messaging.notify_server_credit
{{ if not .oslo_messaging_amqp.oslo.messaging.notify_server_credit }}#{{ end }}notify_server_credit = {{ .oslo_messaging_amqp.oslo.messaging.notify_server_credit | default "100" }}


[oslo_messaging_notifications]

#
# From oslo.messaging
#

# The Drivers(s) to handle sending notifications. Possible values are
# messaging, messagingv2, routing, log, test, noop (multi valued)
# Deprecated group/name - [DEFAULT]/notification_driver
# from .oslo_messaging_notifications.oslo.messaging.driver (multiopt)
{{ if not .oslo_messaging_notifications.oslo.messaging.driver }}#driver = {{ .oslo_messaging_notifications.oslo.messaging.driver | default "" }}{{ else }}{{ range .oslo_messaging_notifications.oslo.messaging.driver }}driver = {{ . }}{{ end }}{{ end }}

# A URL representing the messaging driver to use for notifications. If
# not set, we fall back to the same configuration used for RPC.
# (string value)
# Deprecated group/name - [DEFAULT]/notification_transport_url
# from .oslo_messaging_notifications.oslo.messaging.transport_url
{{ if not .oslo_messaging_notifications.oslo.messaging.transport_url }}#{{ end }}transport_url = {{ .oslo_messaging_notifications.oslo.messaging.transport_url | default "<None>" }}

# AMQP topic used for OpenStack notifications. (list value)
# Deprecated group/name - [rpc_notifier2]/topics
# Deprecated group/name - [DEFAULT]/notification_topics
# from .oslo_messaging_notifications.oslo.messaging.topics
{{ if not .oslo_messaging_notifications.oslo.messaging.topics }}#{{ end }}topics = {{ .oslo_messaging_notifications.oslo.messaging.topics | default "notifications" }}


[oslo_messaging_rabbit]

#
# From oslo.messaging
#

# Use durable queues in AMQP. (boolean value)
# Deprecated group/name - [DEFAULT]/amqp_durable_queues
# Deprecated group/name - [DEFAULT]/rabbit_durable_queues
# from .oslo_messaging_rabbit.oslo.messaging.amqp_durable_queues
{{ if not .oslo_messaging_rabbit.oslo.messaging.amqp_durable_queues }}#{{ end }}amqp_durable_queues = {{ .oslo_messaging_rabbit.oslo.messaging.amqp_durable_queues | default "false" }}

# Auto-delete queues in AMQP. (boolean value)
# Deprecated group/name - [DEFAULT]/amqp_auto_delete
# from .oslo_messaging_rabbit.oslo.messaging.amqp_auto_delete
{{ if not .oslo_messaging_rabbit.oslo.messaging.amqp_auto_delete }}#{{ end }}amqp_auto_delete = {{ .oslo_messaging_rabbit.oslo.messaging.amqp_auto_delete | default "false" }}

# SSL version to use (valid only if SSL enabled). Valid values are
# TLSv1 and SSLv23. SSLv2, SSLv3, TLSv1_1, and TLSv1_2 may be
# available on some distributions. (string value)
# Deprecated group/name - [DEFAULT]/kombu_ssl_version
# from .oslo_messaging_rabbit.oslo.messaging.kombu_ssl_version
{{ if not .oslo_messaging_rabbit.oslo.messaging.kombu_ssl_version }}#{{ end }}kombu_ssl_version = {{ .oslo_messaging_rabbit.oslo.messaging.kombu_ssl_version | default "" }}

# SSL key file (valid only if SSL enabled). (string value)
# Deprecated group/name - [DEFAULT]/kombu_ssl_keyfile
# from .oslo_messaging_rabbit.oslo.messaging.kombu_ssl_keyfile
{{ if not .oslo_messaging_rabbit.oslo.messaging.kombu_ssl_keyfile }}#{{ end }}kombu_ssl_keyfile = {{ .oslo_messaging_rabbit.oslo.messaging.kombu_ssl_keyfile | default "" }}

# SSL cert file (valid only if SSL enabled). (string value)
# Deprecated group/name - [DEFAULT]/kombu_ssl_certfile
# from .oslo_messaging_rabbit.oslo.messaging.kombu_ssl_certfile
{{ if not .oslo_messaging_rabbit.oslo.messaging.kombu_ssl_certfile }}#{{ end }}kombu_ssl_certfile = {{ .oslo_messaging_rabbit.oslo.messaging.kombu_ssl_certfile | default "" }}

# SSL certification authority file (valid only if SSL enabled).
# (string value)
# Deprecated group/name - [DEFAULT]/kombu_ssl_ca_certs
# from .oslo_messaging_rabbit.oslo.messaging.kombu_ssl_ca_certs
{{ if not .oslo_messaging_rabbit.oslo.messaging.kombu_ssl_ca_certs }}#{{ end }}kombu_ssl_ca_certs = {{ .oslo_messaging_rabbit.oslo.messaging.kombu_ssl_ca_certs | default "" }}

# How long to wait before reconnecting in response to an AMQP consumer
# cancel notification. (floating point value)
# Deprecated group/name - [DEFAULT]/kombu_reconnect_delay
# from .oslo_messaging_rabbit.oslo.messaging.kombu_reconnect_delay
{{ if not .oslo_messaging_rabbit.oslo.messaging.kombu_reconnect_delay }}#{{ end }}kombu_reconnect_delay = {{ .oslo_messaging_rabbit.oslo.messaging.kombu_reconnect_delay | default "1.0" }}

# EXPERIMENTAL: Possible values are: gzip, bz2. If not set compression
# will not be used. This option may not be available in future
# versions. (string value)
# from .oslo_messaging_rabbit.oslo.messaging.kombu_compression
{{ if not .oslo_messaging_rabbit.oslo.messaging.kombu_compression }}#{{ end }}kombu_compression = {{ .oslo_messaging_rabbit.oslo.messaging.kombu_compression | default "<None>" }}

# How long to wait a missing client before abandoning to send it its
# replies. This value should not be longer than rpc_response_timeout.
# (integer value)
# Deprecated group/name - [oslo_messaging_rabbit]/kombu_reconnect_timeout
# from .oslo_messaging_rabbit.oslo.messaging.kombu_missing_consumer_retry_timeout
{{ if not .oslo_messaging_rabbit.oslo.messaging.kombu_missing_consumer_retry_timeout }}#{{ end }}kombu_missing_consumer_retry_timeout = {{ .oslo_messaging_rabbit.oslo.messaging.kombu_missing_consumer_retry_timeout | default "60" }}

# Determines how the next RabbitMQ node is chosen in case the one we
# are currently connected to becomes unavailable. Takes effect only if
# more than one RabbitMQ node is provided in config. (string value)
# Allowed values: round-robin, shuffle
# from .oslo_messaging_rabbit.oslo.messaging.kombu_failover_strategy
{{ if not .oslo_messaging_rabbit.oslo.messaging.kombu_failover_strategy }}#{{ end }}kombu_failover_strategy = {{ .oslo_messaging_rabbit.oslo.messaging.kombu_failover_strategy | default "round-robin" }}

# DEPRECATED: The RabbitMQ broker address where a single node is used.
# (string value)
# Deprecated group/name - [DEFAULT]/rabbit_host
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .oslo_messaging_rabbit.oslo.messaging.rabbit_host
{{ if not .oslo_messaging_rabbit.oslo.messaging.rabbit_host }}#{{ end }}rabbit_host = {{ .oslo_messaging_rabbit.oslo.messaging.rabbit_host | default "localhost" }}

# DEPRECATED: The RabbitMQ broker port where a single node is used.
# (port value)
# Minimum value: 0
# Maximum value: 65535
# Deprecated group/name - [DEFAULT]/rabbit_port
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .oslo_messaging_rabbit.oslo.messaging.rabbit_port
{{ if not .oslo_messaging_rabbit.oslo.messaging.rabbit_port }}#{{ end }}rabbit_port = {{ .oslo_messaging_rabbit.oslo.messaging.rabbit_port | default "5672" }}

# DEPRECATED: RabbitMQ HA cluster host:port pairs. (list value)
# Deprecated group/name - [DEFAULT]/rabbit_hosts
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .oslo_messaging_rabbit.oslo.messaging.rabbit_hosts
{{ if not .oslo_messaging_rabbit.oslo.messaging.rabbit_hosts }}#{{ end }}rabbit_hosts = {{ .oslo_messaging_rabbit.oslo.messaging.rabbit_hosts | default "$rabbit_host:$rabbit_port" }}

# Connect over SSL for RabbitMQ. (boolean value)
# Deprecated group/name - [DEFAULT]/rabbit_use_ssl
# from .oslo_messaging_rabbit.oslo.messaging.rabbit_use_ssl
{{ if not .oslo_messaging_rabbit.oslo.messaging.rabbit_use_ssl }}#{{ end }}rabbit_use_ssl = {{ .oslo_messaging_rabbit.oslo.messaging.rabbit_use_ssl | default "false" }}

# DEPRECATED: The RabbitMQ userid. (string value)
# Deprecated group/name - [DEFAULT]/rabbit_userid
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .oslo_messaging_rabbit.oslo.messaging.rabbit_userid
{{ if not .oslo_messaging_rabbit.oslo.messaging.rabbit_userid }}#{{ end }}rabbit_userid = {{ .oslo_messaging_rabbit.oslo.messaging.rabbit_userid | default "guest" }}

# DEPRECATED: The RabbitMQ password. (string value)
# Deprecated group/name - [DEFAULT]/rabbit_password
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .oslo_messaging_rabbit.oslo.messaging.rabbit_password
{{ if not .oslo_messaging_rabbit.oslo.messaging.rabbit_password }}#{{ end }}rabbit_password = {{ .oslo_messaging_rabbit.oslo.messaging.rabbit_password | default "guest" }}

# The RabbitMQ login method. (string value)
# Deprecated group/name - [DEFAULT]/rabbit_login_method
# from .oslo_messaging_rabbit.oslo.messaging.rabbit_login_method
{{ if not .oslo_messaging_rabbit.oslo.messaging.rabbit_login_method }}#{{ end }}rabbit_login_method = {{ .oslo_messaging_rabbit.oslo.messaging.rabbit_login_method | default "AMQPLAIN" }}

# DEPRECATED: The RabbitMQ virtual host. (string value)
# Deprecated group/name - [DEFAULT]/rabbit_virtual_host
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# Reason: Replaced by [DEFAULT]/transport_url
# from .oslo_messaging_rabbit.oslo.messaging.rabbit_virtual_host
{{ if not .oslo_messaging_rabbit.oslo.messaging.rabbit_virtual_host }}#{{ end }}rabbit_virtual_host = {{ .oslo_messaging_rabbit.oslo.messaging.rabbit_virtual_host | default "/" }}

# How frequently to retry connecting with RabbitMQ. (integer value)
# from .oslo_messaging_rabbit.oslo.messaging.rabbit_retry_interval
{{ if not .oslo_messaging_rabbit.oslo.messaging.rabbit_retry_interval }}#{{ end }}rabbit_retry_interval = {{ .oslo_messaging_rabbit.oslo.messaging.rabbit_retry_interval | default "1" }}

# How long to backoff for between retries when connecting to RabbitMQ.
# (integer value)
# Deprecated group/name - [DEFAULT]/rabbit_retry_backoff
# from .oslo_messaging_rabbit.oslo.messaging.rabbit_retry_backoff
{{ if not .oslo_messaging_rabbit.oslo.messaging.rabbit_retry_backoff }}#{{ end }}rabbit_retry_backoff = {{ .oslo_messaging_rabbit.oslo.messaging.rabbit_retry_backoff | default "2" }}

# Maximum interval of RabbitMQ connection retries. Default is 30
# seconds. (integer value)
# from .oslo_messaging_rabbit.oslo.messaging.rabbit_interval_max
{{ if not .oslo_messaging_rabbit.oslo.messaging.rabbit_interval_max }}#{{ end }}rabbit_interval_max = {{ .oslo_messaging_rabbit.oslo.messaging.rabbit_interval_max | default "30" }}

# DEPRECATED: Maximum number of RabbitMQ connection retries. Default
# is 0 (infinite retry count). (integer value)
# Deprecated group/name - [DEFAULT]/rabbit_max_retries
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# from .oslo_messaging_rabbit.oslo.messaging.rabbit_max_retries
{{ if not .oslo_messaging_rabbit.oslo.messaging.rabbit_max_retries }}#{{ end }}rabbit_max_retries = {{ .oslo_messaging_rabbit.oslo.messaging.rabbit_max_retries | default "0" }}

# Try to use HA queues in RabbitMQ (x-ha-policy: all). If you change
# this option, you must wipe the RabbitMQ database. In RabbitMQ 3.0,
# queue mirroring is no longer controlled by the x-ha-policy argument
# when declaring a queue. If you just want to make sure that all
# queues (except  those with auto-generated names) are mirrored across
# all nodes, run: "rabbitmqctl set_policy HA '^(?!amq\.).*' '{"ha-
# mode": "all"}' " (boolean value)
# Deprecated group/name - [DEFAULT]/rabbit_ha_queues
# from .oslo_messaging_rabbit.oslo.messaging.rabbit_ha_queues
{{ if not .oslo_messaging_rabbit.oslo.messaging.rabbit_ha_queues }}#{{ end }}rabbit_ha_queues = {{ .oslo_messaging_rabbit.oslo.messaging.rabbit_ha_queues | default "false" }}

# Positive integer representing duration in seconds for queue TTL
# (x-expires). Queues which are unused for the duration of the TTL are
# automatically deleted. The parameter affects only reply and fanout
# queues. (integer value)
# Minimum value: 1
# from .oslo_messaging_rabbit.oslo.messaging.rabbit_transient_queues_ttl
{{ if not .oslo_messaging_rabbit.oslo.messaging.rabbit_transient_queues_ttl }}#{{ end }}rabbit_transient_queues_ttl = {{ .oslo_messaging_rabbit.oslo.messaging.rabbit_transient_queues_ttl | default "1800" }}

# Specifies the number of messages to prefetch. Setting to zero allows
# unlimited messages. (integer value)
# from .oslo_messaging_rabbit.oslo.messaging.rabbit_qos_prefetch_count
{{ if not .oslo_messaging_rabbit.oslo.messaging.rabbit_qos_prefetch_count }}#{{ end }}rabbit_qos_prefetch_count = {{ .oslo_messaging_rabbit.oslo.messaging.rabbit_qos_prefetch_count | default "0" }}

# Number of seconds after which the Rabbit broker is considered down
# if heartbeat's keep-alive fails (0 disable the heartbeat).
# EXPERIMENTAL (integer value)
# from .oslo_messaging_rabbit.oslo.messaging.heartbeat_timeout_threshold
{{ if not .oslo_messaging_rabbit.oslo.messaging.heartbeat_timeout_threshold }}#{{ end }}heartbeat_timeout_threshold = {{ .oslo_messaging_rabbit.oslo.messaging.heartbeat_timeout_threshold | default "60" }}

# How often times during the heartbeat_timeout_threshold we check the
# heartbeat. (integer value)
# from .oslo_messaging_rabbit.oslo.messaging.heartbeat_rate
{{ if not .oslo_messaging_rabbit.oslo.messaging.heartbeat_rate }}#{{ end }}heartbeat_rate = {{ .oslo_messaging_rabbit.oslo.messaging.heartbeat_rate | default "2" }}

# Deprecated, use rpc_backend=kombu+memory or rpc_backend=fake
# (boolean value)
# Deprecated group/name - [DEFAULT]/fake_rabbit
# from .oslo_messaging_rabbit.oslo.messaging.fake_rabbit
{{ if not .oslo_messaging_rabbit.oslo.messaging.fake_rabbit }}#{{ end }}fake_rabbit = {{ .oslo_messaging_rabbit.oslo.messaging.fake_rabbit | default "false" }}

# Maximum number of channels to allow (integer value)
# from .oslo_messaging_rabbit.oslo.messaging.channel_max
{{ if not .oslo_messaging_rabbit.oslo.messaging.channel_max }}#{{ end }}channel_max = {{ .oslo_messaging_rabbit.oslo.messaging.channel_max | default "<None>" }}

# The maximum byte size for an AMQP frame (integer value)
# from .oslo_messaging_rabbit.oslo.messaging.frame_max
{{ if not .oslo_messaging_rabbit.oslo.messaging.frame_max }}#{{ end }}frame_max = {{ .oslo_messaging_rabbit.oslo.messaging.frame_max | default "<None>" }}

# How often to send heartbeats for consumer's connections (integer
# value)
# from .oslo_messaging_rabbit.oslo.messaging.heartbeat_interval
{{ if not .oslo_messaging_rabbit.oslo.messaging.heartbeat_interval }}#{{ end }}heartbeat_interval = {{ .oslo_messaging_rabbit.oslo.messaging.heartbeat_interval | default "3" }}

# Enable SSL (boolean value)
# from .oslo_messaging_rabbit.oslo.messaging.ssl
{{ if not .oslo_messaging_rabbit.oslo.messaging.ssl }}#{{ end }}ssl = {{ .oslo_messaging_rabbit.oslo.messaging.ssl | default "<None>" }}

# Arguments passed to ssl.wrap_socket (dict value)
# from .oslo_messaging_rabbit.oslo.messaging.ssl_options
{{ if not .oslo_messaging_rabbit.oslo.messaging.ssl_options }}#{{ end }}ssl_options = {{ .oslo_messaging_rabbit.oslo.messaging.ssl_options | default "<None>" }}

# Set socket timeout in seconds for connection's socket (floating
# point value)
# from .oslo_messaging_rabbit.oslo.messaging.socket_timeout
{{ if not .oslo_messaging_rabbit.oslo.messaging.socket_timeout }}#{{ end }}socket_timeout = {{ .oslo_messaging_rabbit.oslo.messaging.socket_timeout | default "0.25" }}

# Set TCP_USER_TIMEOUT in seconds for connection's socket (floating
# point value)
# from .oslo_messaging_rabbit.oslo.messaging.tcp_user_timeout
{{ if not .oslo_messaging_rabbit.oslo.messaging.tcp_user_timeout }}#{{ end }}tcp_user_timeout = {{ .oslo_messaging_rabbit.oslo.messaging.tcp_user_timeout | default "0.25" }}

# Set delay for reconnection to some host which has connection error
# (floating point value)
# from .oslo_messaging_rabbit.oslo.messaging.host_connection_reconnect_delay
{{ if not .oslo_messaging_rabbit.oslo.messaging.host_connection_reconnect_delay }}#{{ end }}host_connection_reconnect_delay = {{ .oslo_messaging_rabbit.oslo.messaging.host_connection_reconnect_delay | default "0.25" }}

# Connection factory implementation (string value)
# Allowed values: new, single, read_write
# from .oslo_messaging_rabbit.oslo.messaging.connection_factory
{{ if not .oslo_messaging_rabbit.oslo.messaging.connection_factory }}#{{ end }}connection_factory = {{ .oslo_messaging_rabbit.oslo.messaging.connection_factory | default "single" }}

# Maximum number of connections to keep queued. (integer value)
# from .oslo_messaging_rabbit.oslo.messaging.pool_max_size
{{ if not .oslo_messaging_rabbit.oslo.messaging.pool_max_size }}#{{ end }}pool_max_size = {{ .oslo_messaging_rabbit.oslo.messaging.pool_max_size | default "30" }}

# Maximum number of connections to create above `pool_max_size`.
# (integer value)
# from .oslo_messaging_rabbit.oslo.messaging.pool_max_overflow
{{ if not .oslo_messaging_rabbit.oslo.messaging.pool_max_overflow }}#{{ end }}pool_max_overflow = {{ .oslo_messaging_rabbit.oslo.messaging.pool_max_overflow | default "0" }}

# Default number of seconds to wait for a connections to available
# (integer value)
# from .oslo_messaging_rabbit.oslo.messaging.pool_timeout
{{ if not .oslo_messaging_rabbit.oslo.messaging.pool_timeout }}#{{ end }}pool_timeout = {{ .oslo_messaging_rabbit.oslo.messaging.pool_timeout | default "30" }}

# Lifetime of a connection (since creation) in seconds or None for no
# recycling. Expired connections are closed on acquire. (integer
# value)
# from .oslo_messaging_rabbit.oslo.messaging.pool_recycle
{{ if not .oslo_messaging_rabbit.oslo.messaging.pool_recycle }}#{{ end }}pool_recycle = {{ .oslo_messaging_rabbit.oslo.messaging.pool_recycle | default "600" }}

# Threshold at which inactive (since release) connections are
# considered stale in seconds or None for no staleness. Stale
# connections are closed on acquire. (integer value)
# from .oslo_messaging_rabbit.oslo.messaging.pool_stale
{{ if not .oslo_messaging_rabbit.oslo.messaging.pool_stale }}#{{ end }}pool_stale = {{ .oslo_messaging_rabbit.oslo.messaging.pool_stale | default "60" }}

# Persist notification messages. (boolean value)
# from .oslo_messaging_rabbit.oslo.messaging.notification_persistence
{{ if not .oslo_messaging_rabbit.oslo.messaging.notification_persistence }}#{{ end }}notification_persistence = {{ .oslo_messaging_rabbit.oslo.messaging.notification_persistence | default "false" }}

# Exchange name for sending notifications (string value)
# from .oslo_messaging_rabbit.oslo.messaging.default_notification_exchange
{{ if not .oslo_messaging_rabbit.oslo.messaging.default_notification_exchange }}#{{ end }}default_notification_exchange = {{ .oslo_messaging_rabbit.oslo.messaging.default_notification_exchange | default "${control_exchange}_notification" }}

# Max number of not acknowledged message which RabbitMQ can send to
# notification listener. (integer value)
# from .oslo_messaging_rabbit.oslo.messaging.notification_listener_prefetch_count
{{ if not .oslo_messaging_rabbit.oslo.messaging.notification_listener_prefetch_count }}#{{ end }}notification_listener_prefetch_count = {{ .oslo_messaging_rabbit.oslo.messaging.notification_listener_prefetch_count | default "100" }}

# Reconnecting retry count in case of connectivity problem during
# sending notification, -1 means infinite retry. (integer value)
# from .oslo_messaging_rabbit.oslo.messaging.default_notification_retry_attempts
{{ if not .oslo_messaging_rabbit.oslo.messaging.default_notification_retry_attempts }}#{{ end }}default_notification_retry_attempts = {{ .oslo_messaging_rabbit.oslo.messaging.default_notification_retry_attempts | default "-1" }}

# Reconnecting retry delay in case of connectivity problem during
# sending notification message (floating point value)
# from .oslo_messaging_rabbit.oslo.messaging.notification_retry_delay
{{ if not .oslo_messaging_rabbit.oslo.messaging.notification_retry_delay }}#{{ end }}notification_retry_delay = {{ .oslo_messaging_rabbit.oslo.messaging.notification_retry_delay | default "0.25" }}

# Time to live for rpc queues without consumers in seconds. (integer
# value)
# from .oslo_messaging_rabbit.oslo.messaging.rpc_queue_expiration
{{ if not .oslo_messaging_rabbit.oslo.messaging.rpc_queue_expiration }}#{{ end }}rpc_queue_expiration = {{ .oslo_messaging_rabbit.oslo.messaging.rpc_queue_expiration | default "60" }}

# Exchange name for sending RPC messages (string value)
# from .oslo_messaging_rabbit.oslo.messaging.default_rpc_exchange
{{ if not .oslo_messaging_rabbit.oslo.messaging.default_rpc_exchange }}#{{ end }}default_rpc_exchange = {{ .oslo_messaging_rabbit.oslo.messaging.default_rpc_exchange | default "${control_exchange}_rpc" }}

# Exchange name for receiving RPC replies (string value)
# from .oslo_messaging_rabbit.oslo.messaging.rpc_reply_exchange
{{ if not .oslo_messaging_rabbit.oslo.messaging.rpc_reply_exchange }}#{{ end }}rpc_reply_exchange = {{ .oslo_messaging_rabbit.oslo.messaging.rpc_reply_exchange | default "${control_exchange}_rpc_reply" }}

# Max number of not acknowledged message which RabbitMQ can send to
# rpc listener. (integer value)
# from .oslo_messaging_rabbit.oslo.messaging.rpc_listener_prefetch_count
{{ if not .oslo_messaging_rabbit.oslo.messaging.rpc_listener_prefetch_count }}#{{ end }}rpc_listener_prefetch_count = {{ .oslo_messaging_rabbit.oslo.messaging.rpc_listener_prefetch_count | default "100" }}

# Max number of not acknowledged message which RabbitMQ can send to
# rpc reply listener. (integer value)
# from .oslo_messaging_rabbit.oslo.messaging.rpc_reply_listener_prefetch_count
{{ if not .oslo_messaging_rabbit.oslo.messaging.rpc_reply_listener_prefetch_count }}#{{ end }}rpc_reply_listener_prefetch_count = {{ .oslo_messaging_rabbit.oslo.messaging.rpc_reply_listener_prefetch_count | default "100" }}

# Reconnecting retry count in case of connectivity problem during
# sending reply. -1 means infinite retry during rpc_timeout (integer
# value)
# from .oslo_messaging_rabbit.oslo.messaging.rpc_reply_retry_attempts
{{ if not .oslo_messaging_rabbit.oslo.messaging.rpc_reply_retry_attempts }}#{{ end }}rpc_reply_retry_attempts = {{ .oslo_messaging_rabbit.oslo.messaging.rpc_reply_retry_attempts | default "-1" }}

# Reconnecting retry delay in case of connectivity problem during
# sending reply. (floating point value)
# from .oslo_messaging_rabbit.oslo.messaging.rpc_reply_retry_delay
{{ if not .oslo_messaging_rabbit.oslo.messaging.rpc_reply_retry_delay }}#{{ end }}rpc_reply_retry_delay = {{ .oslo_messaging_rabbit.oslo.messaging.rpc_reply_retry_delay | default "0.25" }}

# Reconnecting retry count in case of connectivity problem during
# sending RPC message, -1 means infinite retry. If actual retry
# attempts in not 0 the rpc request could be processed more then one
# time (integer value)
# from .oslo_messaging_rabbit.oslo.messaging.default_rpc_retry_attempts
{{ if not .oslo_messaging_rabbit.oslo.messaging.default_rpc_retry_attempts }}#{{ end }}default_rpc_retry_attempts = {{ .oslo_messaging_rabbit.oslo.messaging.default_rpc_retry_attempts | default "-1" }}

# Reconnecting retry delay in case of connectivity problem during
# sending RPC message (floating point value)
# from .oslo_messaging_rabbit.oslo.messaging.rpc_retry_delay
{{ if not .oslo_messaging_rabbit.oslo.messaging.rpc_retry_delay }}#{{ end }}rpc_retry_delay = {{ .oslo_messaging_rabbit.oslo.messaging.rpc_retry_delay | default "0.25" }}


[oslo_messaging_zmq]

#
# From oslo.messaging
#

# ZeroMQ bind address. Should be a wildcard (*), an ethernet
# interface, or IP. The "host" option should point or resolve to this
# address. (string value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_bind_address
# from .oslo_messaging_zmq.oslo.messaging.rpc_zmq_bind_address
{{ if not .oslo_messaging_zmq.oslo.messaging.rpc_zmq_bind_address }}#{{ end }}rpc_zmq_bind_address = {{ .oslo_messaging_zmq.oslo.messaging.rpc_zmq_bind_address | default "*" }}

# MatchMaker driver. (string value)
# Allowed values: redis, dummy
# Deprecated group/name - [DEFAULT]/rpc_zmq_matchmaker
# from .oslo_messaging_zmq.oslo.messaging.rpc_zmq_matchmaker
{{ if not .oslo_messaging_zmq.oslo.messaging.rpc_zmq_matchmaker }}#{{ end }}rpc_zmq_matchmaker = {{ .oslo_messaging_zmq.oslo.messaging.rpc_zmq_matchmaker | default "redis" }}

# Number of ZeroMQ contexts, defaults to 1. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_contexts
# from .oslo_messaging_zmq.oslo.messaging.rpc_zmq_contexts
{{ if not .oslo_messaging_zmq.oslo.messaging.rpc_zmq_contexts }}#{{ end }}rpc_zmq_contexts = {{ .oslo_messaging_zmq.oslo.messaging.rpc_zmq_contexts | default "1" }}

# Maximum number of ingress messages to locally buffer per topic.
# Default is unlimited. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_topic_backlog
# from .oslo_messaging_zmq.oslo.messaging.rpc_zmq_topic_backlog
{{ if not .oslo_messaging_zmq.oslo.messaging.rpc_zmq_topic_backlog }}#{{ end }}rpc_zmq_topic_backlog = {{ .oslo_messaging_zmq.oslo.messaging.rpc_zmq_topic_backlog | default "<None>" }}

# Directory for holding IPC sockets. (string value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_ipc_dir
# from .oslo_messaging_zmq.oslo.messaging.rpc_zmq_ipc_dir
{{ if not .oslo_messaging_zmq.oslo.messaging.rpc_zmq_ipc_dir }}#{{ end }}rpc_zmq_ipc_dir = {{ .oslo_messaging_zmq.oslo.messaging.rpc_zmq_ipc_dir | default "/var/run/openstack" }}

# Name of this node. Must be a valid hostname, FQDN, or IP address.
# Must match "host" option, if running Nova. (string value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_host
# from .oslo_messaging_zmq.oslo.messaging.rpc_zmq_host
{{ if not .oslo_messaging_zmq.oslo.messaging.rpc_zmq_host }}#{{ end }}rpc_zmq_host = {{ .oslo_messaging_zmq.oslo.messaging.rpc_zmq_host | default "localhost" }}

# Seconds to wait before a cast expires (TTL). The default value of -1
# specifies an infinite linger period. The value of 0 specifies no
# linger period. Pending messages shall be discarded immediately when
# the socket is closed. Only supported by impl_zmq. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_cast_timeout
# from .oslo_messaging_zmq.oslo.messaging.rpc_cast_timeout
{{ if not .oslo_messaging_zmq.oslo.messaging.rpc_cast_timeout }}#{{ end }}rpc_cast_timeout = {{ .oslo_messaging_zmq.oslo.messaging.rpc_cast_timeout | default "-1" }}

# The default number of seconds that poll should wait. Poll raises
# timeout exception when timeout expired. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_poll_timeout
# from .oslo_messaging_zmq.oslo.messaging.rpc_poll_timeout
{{ if not .oslo_messaging_zmq.oslo.messaging.rpc_poll_timeout }}#{{ end }}rpc_poll_timeout = {{ .oslo_messaging_zmq.oslo.messaging.rpc_poll_timeout | default "1" }}

# Expiration timeout in seconds of a name service record about
# existing target ( < 0 means no timeout). (integer value)
# Deprecated group/name - [DEFAULT]/zmq_target_expire
# from .oslo_messaging_zmq.oslo.messaging.zmq_target_expire
{{ if not .oslo_messaging_zmq.oslo.messaging.zmq_target_expire }}#{{ end }}zmq_target_expire = {{ .oslo_messaging_zmq.oslo.messaging.zmq_target_expire | default "300" }}

# Update period in seconds of a name service record about existing
# target. (integer value)
# Deprecated group/name - [DEFAULT]/zmq_target_update
# from .oslo_messaging_zmq.oslo.messaging.zmq_target_update
{{ if not .oslo_messaging_zmq.oslo.messaging.zmq_target_update }}#{{ end }}zmq_target_update = {{ .oslo_messaging_zmq.oslo.messaging.zmq_target_update | default "180" }}

# Use PUB/SUB pattern for fanout methods. PUB/SUB always uses proxy.
# (boolean value)
# Deprecated group/name - [DEFAULT]/use_pub_sub
# from .oslo_messaging_zmq.oslo.messaging.use_pub_sub
{{ if not .oslo_messaging_zmq.oslo.messaging.use_pub_sub }}#{{ end }}use_pub_sub = {{ .oslo_messaging_zmq.oslo.messaging.use_pub_sub | default "true" }}

# Use ROUTER remote proxy. (boolean value)
# Deprecated group/name - [DEFAULT]/use_router_proxy
# from .oslo_messaging_zmq.oslo.messaging.use_router_proxy
{{ if not .oslo_messaging_zmq.oslo.messaging.use_router_proxy }}#{{ end }}use_router_proxy = {{ .oslo_messaging_zmq.oslo.messaging.use_router_proxy | default "true" }}

# Minimal port number for random ports range. (port value)
# Minimum value: 0
# Maximum value: 65535
# Deprecated group/name - [DEFAULT]/rpc_zmq_min_port
# from .oslo_messaging_zmq.oslo.messaging.rpc_zmq_min_port
{{ if not .oslo_messaging_zmq.oslo.messaging.rpc_zmq_min_port }}#{{ end }}rpc_zmq_min_port = {{ .oslo_messaging_zmq.oslo.messaging.rpc_zmq_min_port | default "49153" }}

# Maximal port number for random ports range. (integer value)
# Minimum value: 1
# Maximum value: 65536
# Deprecated group/name - [DEFAULT]/rpc_zmq_max_port
# from .oslo_messaging_zmq.oslo.messaging.rpc_zmq_max_port
{{ if not .oslo_messaging_zmq.oslo.messaging.rpc_zmq_max_port }}#{{ end }}rpc_zmq_max_port = {{ .oslo_messaging_zmq.oslo.messaging.rpc_zmq_max_port | default "65536" }}

# Number of retries to find free port number before fail with
# ZMQBindError. (integer value)
# Deprecated group/name - [DEFAULT]/rpc_zmq_bind_port_retries
# from .oslo_messaging_zmq.oslo.messaging.rpc_zmq_bind_port_retries
{{ if not .oslo_messaging_zmq.oslo.messaging.rpc_zmq_bind_port_retries }}#{{ end }}rpc_zmq_bind_port_retries = {{ .oslo_messaging_zmq.oslo.messaging.rpc_zmq_bind_port_retries | default "100" }}

# Default serialization mechanism for serializing/deserializing
# outgoing/incoming messages (string value)
# Allowed values: json, msgpack
# Deprecated group/name - [DEFAULT]/rpc_zmq_serialization
# from .oslo_messaging_zmq.oslo.messaging.rpc_zmq_serialization
{{ if not .oslo_messaging_zmq.oslo.messaging.rpc_zmq_serialization }}#{{ end }}rpc_zmq_serialization = {{ .oslo_messaging_zmq.oslo.messaging.rpc_zmq_serialization | default "json" }}

# This option configures round-robin mode in zmq socket. True means
# not keeping a queue when server side disconnects. False means to
# keep queue and messages even if server is disconnected, when the
# server appears we send all accumulated messages to it. (boolean
# value)
# from .oslo_messaging_zmq.oslo.messaging.zmq_immediate
{{ if not .oslo_messaging_zmq.oslo.messaging.zmq_immediate }}#{{ end }}zmq_immediate = {{ .oslo_messaging_zmq.oslo.messaging.zmq_immediate | default "false" }}


[oslo_middleware]

#
# From oslo.middleware
#

# The maximum body size for each  request, in bytes. (integer value)
# Deprecated group/name - [DEFAULT]/osapi_max_request_body_size
# Deprecated group/name - [DEFAULT]/max_request_body_size
# from .oslo_middleware.oslo.middleware.max_request_body_size
{{ if not .oslo_middleware.oslo.middleware.max_request_body_size }}#{{ end }}max_request_body_size = {{ .oslo_middleware.oslo.middleware.max_request_body_size | default "114688" }}

# DEPRECATED: The HTTP Header that will be used to determine what the
# original request protocol scheme was, even if it was hidden by a SSL
# termination proxy. (string value)
# This option is deprecated for removal.
# Its value may be silently ignored in the future.
# from .oslo_middleware.oslo.middleware.secure_proxy_ssl_header
{{ if not .oslo_middleware.oslo.middleware.secure_proxy_ssl_header }}#{{ end }}secure_proxy_ssl_header = {{ .oslo_middleware.oslo.middleware.secure_proxy_ssl_header | default "X-Forwarded-Proto" }}

# Whether the application is behind a proxy or not. This determines if
# the middleware should parse the headers or not. (boolean value)
# from .oslo_middleware.oslo.middleware.enable_proxy_headers_parsing
{{ if not .oslo_middleware.oslo.middleware.enable_proxy_headers_parsing }}#{{ end }}enable_proxy_headers_parsing = {{ .oslo_middleware.oslo.middleware.enable_proxy_headers_parsing | default "false" }}


[oslo_policy]

#
# From oslo.policy
#

# The JSON file that defines policies. (string value)
# Deprecated group/name - [DEFAULT]/policy_file
# from .oslo_policy.oslo.policy.policy_file
{{ if not .oslo_policy.oslo.policy.policy_file }}#{{ end }}policy_file = {{ .oslo_policy.oslo.policy.policy_file | default "policy.json" }}

# Default rule. Enforced when a requested rule is not found. (string
# value)
# Deprecated group/name - [DEFAULT]/policy_default_rule
# from .oslo_policy.oslo.policy.policy_default_rule
{{ if not .oslo_policy.oslo.policy.policy_default_rule }}#{{ end }}policy_default_rule = {{ .oslo_policy.oslo.policy.policy_default_rule | default "default" }}

# Directories where policy configuration files are stored. They can be
# relative to any directory in the search path defined by the
# config_dir option, or absolute paths. The file defined by
# policy_file must exist for these directories to be searched.
# Missing or empty directories are ignored. (multi valued)
# Deprecated group/name - [DEFAULT]/policy_dirs
# from .oslo_policy.oslo.policy.policy_dirs (multiopt)
{{ if not .oslo_policy.oslo.policy.policy_dirs }}#policy_dirs = {{ .oslo_policy.oslo.policy.policy_dirs | default "policy.d" }}{{ else }}{{ range .oslo_policy.oslo.policy.policy_dirs }}policy_dirs = {{ . }}{{ end }}{{ end }}


[oslo_reports]

#
# From oslo.reports
#

# Path to a log directory where to create a file (string value)
# from .oslo_reports.oslo.reports.log_dir
{{ if not .oslo_reports.oslo.reports.log_dir }}#{{ end }}log_dir = {{ .oslo_reports.oslo.reports.log_dir | default "<None>" }}

# The path to a file to watch for changes to trigger the reports,
# instead of signals. Setting this option disables the signal trigger
# for the reports. If application is running as a WSGI application it
# is recommended to use this instead of signals. (string value)
# from .oslo_reports.oslo.reports.file_event_handler
{{ if not .oslo_reports.oslo.reports.file_event_handler }}#{{ end }}file_event_handler = {{ .oslo_reports.oslo.reports.file_event_handler | default "<None>" }}

# How many seconds to wait between polls when file_event_handler is
# set (integer value)
# from .oslo_reports.oslo.reports.file_event_handler_interval
{{ if not .oslo_reports.oslo.reports.file_event_handler_interval }}#{{ end }}file_event_handler_interval = {{ .oslo_reports.oslo.reports.file_event_handler_interval | default "1" }}


[oslo_versionedobjects]

#
# From oslo.versionedobjects
#

# Make exception message format errors fatal (boolean value)
# from .oslo_versionedobjects.oslo.versionedobjects.fatal_exception_format_errors
{{ if not .oslo_versionedobjects.oslo.versionedobjects.fatal_exception_format_errors }}#{{ end }}fatal_exception_format_errors = {{ .oslo_versionedobjects.oslo.versionedobjects.fatal_exception_format_errors | default "false" }}


[ssl]

#
# From oslo.service.sslutils
#

# CA certificate file to use to verify connecting clients. (string
# value)
# Deprecated group/name - [DEFAULT]/ssl_ca_file
# from .ssl.oslo.service.sslutils.ca_file
{{ if not .ssl.oslo.service.sslutils.ca_file }}#{{ end }}ca_file = {{ .ssl.oslo.service.sslutils.ca_file | default "<None>" }}

# Certificate file to use when starting the server securely. (string
# value)
# Deprecated group/name - [DEFAULT]/ssl_cert_file
# from .ssl.oslo.service.sslutils.cert_file
{{ if not .ssl.oslo.service.sslutils.cert_file }}#{{ end }}cert_file = {{ .ssl.oslo.service.sslutils.cert_file | default "<None>" }}

# Private key file to use when starting the server securely. (string
# value)
# Deprecated group/name - [DEFAULT]/ssl_key_file
# from .ssl.oslo.service.sslutils.key_file
{{ if not .ssl.oslo.service.sslutils.key_file }}#{{ end }}key_file = {{ .ssl.oslo.service.sslutils.key_file | default "<None>" }}

# SSL version to use (valid only if SSL enabled). Valid values are
# TLSv1 and SSLv23. SSLv2, SSLv3, TLSv1_1, and TLSv1_2 may be
# available on some distributions. (string value)
# from .ssl.oslo.service.sslutils.version
{{ if not .ssl.oslo.service.sslutils.version }}#{{ end }}version = {{ .ssl.oslo.service.sslutils.version | default "<None>" }}

# Sets the list of available ciphers. value should be a string in the
# OpenSSL cipher list format. (string value)
# from .ssl.oslo.service.sslutils.ciphers
{{ if not .ssl.oslo.service.sslutils.ciphers }}#{{ end }}ciphers = {{ .ssl.oslo.service.sslutils.ciphers | default "<None>" }}

{{- end -}}

