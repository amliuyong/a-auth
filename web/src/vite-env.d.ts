/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** 后端 API base URL(同源部署留空;本地开发指向后端,如真机 API Gateway)。 */
  readonly VITE_API_BASE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
