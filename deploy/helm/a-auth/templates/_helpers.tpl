{{- define "a-auth.name" -}}
{{- printf "%s-a-auth" .Release.Name | trunc 48 | trimSuffix "-" -}}
{{- end -}}
{{- define "a-auth.image" -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" .Values.image.digest) -}}
{{- fail "image.digest must be an immutable sha256 digest" -}}
{{- end -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- end -}}
{{- define "a-auth.frontendImage" -}}
{{- if not (regexMatch "^sha256:[0-9a-f]{64}$" .Values.frontend.image.digest) -}}
{{- fail "frontend.image.digest must be an immutable sha256 digest" -}}
{{- end -}}
{{- if not (regexMatch "^[0-9a-f]{40}$" .Values.frontend.image.sourceCommit) -}}
{{- fail "frontend.image.sourceCommit must contain forty lowercase hexadecimal characters" -}}
{{- end -}}
{{- printf "%s@%s" .Values.frontend.image.repository .Values.frontend.image.digest -}}
{{- end -}}
{{- define "a-auth.labels" -}}
app.kubernetes.io/name: a-auth
app.kubernetes.io/instance: {{ .Release.Name | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service | quote }}
{{- end -}}
