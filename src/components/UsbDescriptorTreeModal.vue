<template>
  <div v-if="isOpen" class="ui-modal-backdrop fixed inset-0 z-50 flex items-center justify-center p-4">
    <div class="ui-modal-surface relative w-full max-w-3xl rounded-3xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
      <span class="lens-edge-lip" aria-hidden="true"></span>
      <!-- 头部 -->
      <div class="ui-nav-glass px-6 py-4 border-b border-(--border-subtle) flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-purple-500/12 border border-purple-500/30 flex items-center justify-center text-purple-600 dark:text-purple-400">
            <AppIcon name="usb" class="w-4 h-4" />
          </div>
          <div>
            <h3 class="text-sm font-bold text-(--text-primary)">USB 标准描述符树深度展开分析器</h3>
            <p class="text-xs text-(--text-muted) font-mono-code">递归解析 Device -> Configuration -> Interface -> Endpoint 四级标准结构</p>
          </div>
        </div>
        <button @click="$emit('close')" class="ui-btn-secondary w-8 h-8 rounded-full p-0 flex items-center justify-center cursor-pointer" aria-label="关闭弹窗">
          <AppIcon name="close" class="w-4 h-4" />
        </button>
      </div>

      <!-- 主体内容 -->
      <div class="p-6 space-y-4 overflow-auto max-h-[75vh] custom-scrollbar">
        <!-- 载荷输入与预设 -->
        <div class="ui-sub-card border-purple-500/30 rounded-2xl p-3.5 flex flex-col gap-2.5">
          <div class="flex flex-wrap items-center justify-between gap-2 text-xs">
            <span class="font-bold text-(--text-primary)">标准描述符原始 HEX 字节流:</span>
            <div class="flex flex-wrap gap-1.5 text-[11px]">
              <button @click="loadSample('hid_mouse')" class="ui-btn-secondary px-2.5 py-0.5 text-[11px] cursor-pointer">
                HID 鼠标描述符
              </button>
              <button @click="loadSample('mass_storage')" class="ui-btn-secondary px-2.5 py-0.5 text-[11px] cursor-pointer">
                U 盘存储描述符
              </button>
              <button @click="loadSample('cdc_serial')" class="ui-btn-secondary px-2.5 py-0.5 text-[11px] cursor-pointer">
                CDC 虚拟串口描述符
              </button>
            </div>
          </div>
          <textarea v-model="rawHex" rows="2" placeholder="输入 USB 标准描述符连续十六进制字节流 (包含 0x12 长度 Device 描述符与 0x09 长度 Config 描述符)"
            class="ui-input w-full p-2.5 text-xs font-mono-code select-text"></textarea>
          <div class="flex items-center gap-2 flex-wrap">
            <button @click="doParseTree" :disabled="isParsing || !rawHex.trim()"
              class="ui-btn-primary text-xs py-1.5 px-4 font-bold inline-flex items-center justify-center gap-1.5 cursor-pointer disabled:opacity-40">
              <AppIcon v-if="isParsing" name="refresh" class="w-3.5 h-3.5 animate-spin" />
              <span>执行递归描述符树剖析</span>
            </button>
            <button @click="addDescriptorToDiffQueue" :disabled="!rawHex.trim()"
              class="ui-btn-secondary text-xs py-1.5 px-3 font-semibold inline-flex items-center gap-1.5 cursor-pointer disabled:opacity-40"
              title="将当前 USB 描述符原始 HEX 送入全局多组比对队列（支持与其他 USB 设备进行 Center-Star 对齐比对）">
              <AppIcon name="scale" class="w-3.5 h-3.5" />
              <span>+ 加入全局比对队列</span>
            </button>
          </div>
        </div>

        <!-- 错误提示 -->
        <div v-if="errorMsg" class="p-3 rounded-xl bg-rose-500/12 border border-rose-500/30 text-rose-700 dark:text-rose-300 text-xs font-mono-code select-text">
          {{ errorMsg }}
        </div>

        <!-- 描述符树可视化展开 -->
        <div v-if="descriptorTree" class="space-y-3 font-mono-code text-xs">
          <!-- 1. Device Descriptor (根节点) -->
          <div class="ui-content-card border-purple-500/35 rounded-2xl p-3.5 flex flex-col gap-2">
            <div class="flex items-center justify-between border-b border-(--border-subtle) pb-2 gap-2">
              <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 bg-purple-500/12 text-purple-700 dark:text-purple-300 border border-purple-500/30 rounded font-bold text-[11px]">DEVICE (0x01)</span>
                <span class="font-bold text-(--text-primary) font-sans">设备描述符 (Device Descriptor)</span>
              </div>
              <span class="text-purple-600 dark:text-purple-400 font-bold text-xs ui-num select-text">
                VID: {{ descriptorTree.device.vendor_id }} | PID: {{ descriptorTree.device.product_id }}
              </span>
            </div>

            <div class="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px] text-(--text-secondary) ui-sub-card p-2.5 rounded-xl ui-num select-text">
              <div>USB 规范版本: <strong class="text-(--text-primary)">{{ descriptorTree.device.bcd_usb }}</strong></div>
              <div>设备类别代码: <strong class="text-(--text-primary)">0x{{ descriptorTree.device.device_class.toString(16).padStart(2, '0').toUpperCase() }}</strong></div>
              <div>子类别: <strong class="text-(--text-primary)">0x{{ descriptorTree.device.device_subclass.toString(16).padStart(2, '0').toUpperCase() }}</strong></div>
              <div>协议代码: <strong class="text-(--text-primary)">0x{{ descriptorTree.device.device_protocol.toString(16).padStart(2, '0').toUpperCase() }}</strong></div>
              <div>EP0 最大包长: <strong class="text-(--text-primary)">{{ descriptorTree.device.max_packet_size0 }} 字节</strong></div>
              <div>设备版本号: <strong class="text-(--text-primary)">{{ descriptorTree.device.bcd_device }}</strong></div>
              <div>配置描述符数: <strong class="text-purple-600 dark:text-purple-400 font-bold">{{ descriptorTree.device.num_configurations }}</strong></div>
              <div>厂商/产品/串号: <span class="text-(--text-muted)">i{{ descriptorTree.device.manufacturer_idx }}/i{{ descriptorTree.device.product_idx }}/i{{ descriptorTree.device.serial_idx }}</span></div>
            </div>
          </div>

          <!-- 2. Configuration Descriptors (二级节点) -->
          <div v-for="cfg in descriptorTree.configurations" :key="cfg.config_descriptor.config_value"
            class="ui-content-card border-sky-500/30 rounded-2xl p-3.5 flex flex-col gap-2.5 ml-4 border-l-4 border-l-sky-500">
            <div class="flex items-center justify-between border-b border-(--border-subtle) pb-2 gap-2">
              <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 bg-sky-500/12 text-sky-700 dark:text-sky-300 border border-sky-500/30 rounded font-bold text-[11px]">CONFIG (0x02)</span>
                <span class="font-bold text-(--text-primary) font-sans">配置描述符 #{{ cfg.config_descriptor.config_value }}</span>
              </div>
              <span class="text-sky-600 dark:text-sky-400 font-bold text-xs ui-num select-text">
                总长度: {{ cfg.config_descriptor.total_length }} 字节 | 接口数: {{ cfg.config_descriptor.num_interfaces }}
              </span>
            </div>

            <div class="grid grid-cols-2 md:grid-cols-3 gap-2 text-[11px] text-(--text-secondary) ui-sub-card p-2.5 rounded-xl ui-num select-text">
              <div>供电属性: <strong class="text-(--text-primary)">0x{{ cfg.config_descriptor.attributes.toString(16).padStart(2, '0').toUpperCase() }} ({{ (cfg.config_descriptor.attributes & 0x40) ? '自供电' : '总线供电' }})</strong></div>
              <div>最大功耗: <strong class="text-sky-600 dark:text-sky-400">{{ cfg.config_descriptor.max_power_ma }} mA</strong></div>
              <div>配置索引: <span class="text-(--text-muted)">i{{ cfg.config_descriptor.config_str_idx }}</span></div>
            </div>

            <!-- 3. Interface Descriptors (三级节点) -->
            <div v-for="iface in cfg.interfaces" :key="iface.interface_descriptor.interface_number"
              class="ui-content-card border-emerald-500/30 rounded-xl p-3 flex flex-col gap-2 ml-4 border-l-4 border-l-emerald-500">
              <div class="flex items-center justify-between border-b border-(--border-subtle) pb-1.5 gap-2">
                <div class="flex items-center gap-2">
                  <span class="px-2 py-0.5 bg-emerald-500/12 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30 rounded font-bold text-[11px]">INTERFACE (0x04)</span>
                  <span class="font-bold text-(--text-primary) font-sans">接口 #{{ iface.interface_descriptor.interface_number }} (Alt {{ iface.interface_descriptor.alternate_setting }})</span>
                </div>
                <span class="text-emerald-600 dark:text-emerald-400 font-bold text-xs ui-num select-text">
                  端点数: {{ iface.interface_descriptor.num_endpoints }} | 类别: 0x{{ iface.interface_descriptor.interface_class.toString(16).padStart(2, '0').toUpperCase() }}
                </span>
              </div>

              <!-- 4. Endpoint Descriptors (四级叶节点) -->
              <div class="grid grid-cols-1 md:grid-cols-2 gap-2 mt-1">
                <div v-for="ep in iface.endpoints" :key="ep.endpoint_address"
                  class="ui-sub-card rounded-lg p-2.5 flex items-center justify-between">
                  <div class="flex items-center gap-2">
                    <span class="w-2 h-2 rounded-full" :class="ep.direction === 'IN' ? 'bg-sky-500' : 'bg-emerald-500'"></span>
                    <div>
                      <div class="font-bold text-(--text-primary) text-xs ui-num select-text">
                        端点 0x{{ ep.endpoint_address.toString(16).padStart(2, '0').toUpperCase() }} [{{ ep.direction }}]
                      </div>
                      <div class="text-[11px] text-(--text-muted) ui-num">
                        类型: {{ ep.transfer_type }} | 间隔: {{ ep.interval_ms }}ms
                      </div>
                    </div>
                  </div>
                  <div class="text-right ui-num">
                    <div class="font-bold text-xs text-(--text-primary)">{{ ep.max_packet_size }} 字节</div>
                    <div class="text-[11px] text-(--text-muted)">Max Packet</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 底部操作 -->
      <div class="px-6 py-3 border-t border-(--border-subtle) bg-(--surface-content-alt) flex items-center justify-end shrink-0">
        <button @click="$emit('close')" class="ui-btn-secondary px-4 py-1.5 text-xs font-semibold cursor-pointer">
          关闭
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';
import AppIcon from './AppIcon.vue';
import { useUniversalDiff } from '../composables/useUniversalDiff';

const diffBus = useUniversalDiff();

export interface UsbDeviceDescriptor {
  length: number;
  descriptor_type: number;
  bcd_usb: string;
  device_class: number;
  device_subclass: number;
  device_protocol: number;
  max_packet_size0: number;
  vendor_id: string;
  product_id: string;
  bcd_device: string;
  manufacturer_idx: number;
  product_idx: number;
  serial_idx: number;
  num_configurations: number;
}

export interface UsbEndpointDescriptor {
  length: number;
  descriptor_type: number;
  endpoint_address: number;
  direction: string;
  transfer_type: string;
  attributes: number;
  max_packet_size: number;
  interval_ms: number;
}

export interface UsbInterfaceNode {
  interface_descriptor: {
    length: number;
    descriptor_type: number;
    interface_number: number;
    alternate_setting: number;
    num_endpoints: number;
    interface_class: number;
    interface_subclass: number;
    interface_protocol: number;
    interface_str_idx: number;
  };
  endpoints: UsbEndpointDescriptor[];
}

export interface UsbConfigurationNode {
  config_descriptor: {
    length: number;
    descriptor_type: number;
    total_length: number;
    num_interfaces: number;
    config_value: number;
    config_str_idx: number;
    attributes: number;
    max_power_ma: number;
  };
  interfaces: UsbInterfaceNode[];
}

export interface UsbDescriptorTree {
  device: UsbDeviceDescriptor;
  configurations: UsbConfigurationNode[];
}

const props = defineProps<{
  isOpen: boolean;
  initialHex?: string;
}>();

defineEmits(['close']);

const rawHex = ref(props.initialHex || '12 01 00 02 00 00 00 40 86 80 20 08 00 01 01 02 00 01 09 02 22 00 01 01 00 A0 32 09 04 00 00 01 03 01 02 00 07 05 81 03 08 00 0A');
const isParsing = ref(false);
const errorMsg = ref<string | null>(null);
const descriptorTree = ref<UsbDescriptorTree | null>(null);

function loadSample(type: 'hid_mouse' | 'mass_storage' | 'cdc_serial') {
  if (type === 'hid_mouse') {
    rawHex.value = '12 01 00 02 00 00 00 40 86 80 20 08 00 01 01 02 00 01 09 02 22 00 01 01 00 A0 32 09 04 00 00 01 03 01 02 00 07 05 81 03 08 00 0A';
  } else if (type === 'mass_storage') {
    rawHex.value = '12 01 10 02 00 00 00 40 51 09 63 16 00 01 01 02 03 01 09 02 20 00 01 01 00 C0 32 09 04 00 00 02 08 06 50 00 07 05 81 02 40 00 00 07 05 02 02 40 00 00';
  } else if (type === 'cdc_serial') {
    rawHex.value = '12 01 00 02 02 00 00 40 86 1A 23 75 00 02 01 02 03 01 09 02 43 00 02 01 00 80 32 09 04 00 00 01 02 02 01 00 07 05 82 03 0A 00 01 09 04 01 00 02 0A 00 00 00 07 05 02 02 40 00 00 07 05 82 02 40 00 00';
  }
  doParseTree();
}

async function doParseTree() {
  if (!rawHex.value.trim() || isParsing.value) return;
  isParsing.value = true;
  errorMsg.value = null;

  try {
    const res = await invoke<UsbDescriptorTree>('parse_usb_descriptor_tree_cmd', {
      rawHex: rawHex.value.trim(),
    });
    descriptorTree.value = res;
  } catch (err: any) {
    errorMsg.value = `解析描述符树失败: ${err?.message || String(err)}`;
  } finally {
    isParsing.value = false;
  }
}

function addDescriptorToDiffQueue() {
  const cleanHex = rawHex.value.replace(/[\s\r\n\t]/g, '');
  if (!cleanHex) return;
  const vidPid = descriptorTree.value
    ? `${descriptorTree.value.device.vendor_id}:${descriptorTree.value.device.product_id}`
    : 'RAW_DESC';
  diffBus.addToQueue({
    id: `USB_DESC_${vidPid}_${Date.now()}`,
    label: `[USB描述符] ${vidPid}`,
    protocol: 'USB-DESCRIPTOR',
    src: vidPid,
    dst: `USB ${descriptorTree.value?.device.bcd_usb || '2.0'}`,
    payloadHex: cleanHex,
    length: cleanHex.length / 2,
    extraFields: descriptorTree.value ? {
      vendor_id: descriptorTree.value.device.vendor_id,
      product_id: descriptorTree.value.device.product_id,
      bcd_usb: descriptorTree.value.device.bcd_usb,
      device_class: String(descriptorTree.value.device.device_class),
      max_packet_size0: String(descriptorTree.value.device.max_packet_size0),
      num_configurations: String(descriptorTree.value.device.num_configurations)
    } : {}
  }, `USB 描述符 ${vidPid}`, false);
}

onMounted(() => {
  if (rawHex.value.trim()) {
    doParseTree();
  }
});
</script>
