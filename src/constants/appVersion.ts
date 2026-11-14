import packageJson from '../../package.json';

/**
 * Omni-Probe 全局版本号定义
 * 源自 package.json 统一版本号单真理源 (Single Source of Truth)
 * 严禁在任何组件、模态框、状态栏或网络报文中硬编码版本号
 */
export const APP_VERSION_RAW: string = packageJson.version;
export const APP_VERSION: string = `v${packageJson.version}`;
export const APP_FULL_NAME: string = `Omni-Probe 工业级全能网络探针系统 ${APP_VERSION}`;
