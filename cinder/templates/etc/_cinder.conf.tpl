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

[DEFAULT]
debug = {{ .Values.misc.debug }}
use_syslog = False
use_stderr = True

enable_v1_api = false
volume_name_template = %s

osapi_volume_workers = {{ .Values.api.workers }}
osapi_volume_listen = 0.0.0.0
osapi_volume_listen_port = {{ .Values.network.port.api }}

api_paste_config = /etc/cinder/api-paste.ini

glance_api_servers = {{ tuple "image" "internal" "api" . | include "helm-toolkit.keystone_endpoint_uri_lookup" }}
glance_api_version = {{ .Values.glance.version }}

enabled_backends = {{  include "helm-toolkit.joinMapKeysWithComma" .Values.backends}}

auth_strategy = keystone
os_region_name = {{ .Values.keystone.cinder_region_name }}

# ensures that our volume worker service-list doesn't
# explode with dead agents from terminated containers
# by pinning the agent identifier
host=cinder-volume-worker

[database]
connection = mysql+pymysql://{{ .Values.database.cinder_user }}:{{ .Values.database.cinder_password }}@{{ .Values.database.address }}:{{ .Values.database.port }}/{{ .Values.database.cinder_database_name }}
max_retries = -1

[keystone_authtoken]
auth_version = v3
auth_url = {{ tuple "identity" "internal" "api" . | include "helm-toolkit.keystone_endpoint_uri_lookup" }}
auth_type = password
region_name = {{ .Values.keystone.cinder_region_name }}
project_domain_name = {{ .Values.keystone.cinder_project_domain }}
project_name = {{ .Values.keystone.cinder_project_name }}
user_domain_name = {{ .Values.keystone.cinder_user_domain }}
username = {{ .Values.keystone.cinder_user }}
password = {{ .Values.keystone.cinder_password }}

[oslo_concurrency]
lock_path = /var/lib/cinder/tmp

[oslo_messaging_rabbit]
rabbit_userid = {{ .Values.messaging.user }}
rabbit_password = {{ .Values.messaging.password }}
rabbit_ha_queues = true
rabbit_hosts = {{ .Values.messaging.hosts }}

{{ range $name, $options := .Values.backends }}
[{{ $name }}]
{{- if not $options.volume_backend_name }}
volume_backend_name = {{ $name }}
{{- end }}
{{- if not $options.volume_driver }}
volume_driver = "cinder.volume.driver.rbd.RBDDriver"
{{- end }}

{{- if eq $options.volume_driver "cinder.volume.drivers.rbd.RBDDriver" }}
{{- if not $options.rbd_ceph_conf }}
rbd_ceph_conf = /etc/ceph/ceph.conf
{{- end }}
{{- if not $options.rbd_flatten_volume_from_snapshot }}
rbd_flatten_volume_from_snapshot = false
{{- end }}
{{- if not $options.rbd_max_clone_depth }}
rbd_max_clone_depth = 5
{{- end }}
{{- if not $options.rbd_store_chunk_size }}
rbd_store_chunk_size = 4
{{- end }}
{{- if not $options.rados_connect_timeout }}
rados_connect_timeout = -1
{{- end }}
{{- if not $options.report_discard_supported }}
report_discard_supported = True
{{- end }}

{{- if $options.rbd_secret_uuid }}
rbd_user = {{ $options.rbd_user }}
rbd_secret_uuid = {{- $options.rbd_secret_uuid -}}
{{- else }}
rbd_secret_uuid = {{- include "secrets/ceph-client-key" . -}}
{{- end }}
{{- end }}

{{- range $key, $value := $options }}
{{- if $value }}
{{ $key }} = {{ $value }}
{{- end }}
{{- end }}
{{ end }}
