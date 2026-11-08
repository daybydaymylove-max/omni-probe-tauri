<template>
  <div v-if="isOpen" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-md">
    <div class="w-full max-w-3xl bg-white/95 backdrop-blur-2xl rounded-3xl border border-white/60 shadow-2xl flex flex-col overflow-hidden animate-in fade-in zoom-in-95 duration-150">
      <!-- 头部 -->
      <div class="px-6 py-4 border-b border-slate-200/60 bg-white/40 flex items-center justify-between shrink-0">
        <div class="flex items-center gap-2.5">
          <div class="w-8 h-8 rounded-xl bg-purple-50 border border-purple-200 flex items-center justify-center text-purple-700 text-sm font-bold shadow-2xs">
            🌲
          </div>
          <div>
            <h3 class="text-sm font-bold text-slate-900">USB 标准描述符树深度展开分析器</h3>
            <p class="text-[11px] text-slate-500 font-mono">递归解析 Device ➔ Configuration ➔ Interface ➔ Endpoint 四级标准描述符结构</p>
          </div>
        </div>
        <button @click="$emit('close')" class="w-8 h-8 rounded-full flex items-center justify-center text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition-colors cursor-pointer">
          ✕
        </button>
      </div>

      <!-- 主体内容 -->
      <div class="p-6 space-y-4 overflow-auto max-h-[75vh] custom-scrollbar">
        <!-- 载荷输入与预设 -->
        <div class="bg-purple-50/60 border border-purple-100 rounded-2xl p-3.5 flex flex-col gap-2.5">
          <div class="flex items-center justify-between text-xs">
            <span class="font-bold text-purple-950">标准描述符原始 HEX 字节流:</span>
            <div class="flex gap-1.5 text-[11px]">
              <button @click="loadSample('hid_mouse')" class="bg-white hover:bg-purple-100 text-purple-900 border border-purple-200 px-2 py-0.5 rounded-lg cursor-pointer shadow-2xs">
                HID 鼠标描述符
              </button>
              <button @click="loadSample('mass_storage')" class="bg-white hover:bg-purple-100 text-purple-900 border border-purple-200 px-2 py-0.5 rounded-lg cursor-pointer shadow-2xs">
                U 盘存储描述符
              </button>
              <button @click="loadSample('cdc_serial')" class="bg-white hover:bg-purple-100 text-purple-900 border border-purple-200 px-2 py-0.5 rounded-lg cursor-pointer shadow-2xs">
                CDC 虚拟串口描述符
              </button>
            </div>
          </div>
          <textarea v-model="rawHex" rows="2" placeholder="输入 USB 标准描述符连续十六进制字节流 (包含 0x12 长度 Device 描述符与 0x09 长度 Config 描述符)"
            class="w-full bg-white border border-slate-200 rounded-xl p-2.5 text-xs font-mono text-slate-800 focus:outline-none focus:ring-2 focus:ring-purple-500/30 shadow-2xs"></textarea>
          <button @click="doParseTree" :disabled="isParsing || !rawHex.trim()"
            class="bg-purple-600 hover:bg-purple-700 text-white text-xs py-1.5 rounded-xl font-bold transition-all shadow-sm active:scale-95 disabled:opacity-40 cursor-pointer flex items-center justify-center gap-1">
            <span v-if="isParsing" class="animate-spin">⏳ </span>
            <span>执行递归描述符树剖析</span>
          </button>
        </div>

        <!-- 错误提示 -->
        <div v-if="errorMsg" class="p-3 rounded-xl bg-rose-50 border border-rose-200 text-rose-800 text-xs font-mono">
          {{ errorMsg }}
        </div>

        <!-- 描述符树可视化展开 -->
        <div v-if="descriptorTree" class="space-y-3 font-mono text-xs">
          <!-- 1. Device Descriptor (根节点) -->
          <div class="bg-white border border-purple-200 rounded-2xl p-3.5 shadow-2xs flex flex-col gap-2">
            <div class="flex items-center justify-between border-b border-purple-100 pb-2">
              <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 bg-purple-100 text-purple-800 rounded font-bold text-[10px]">DEVICE (0x01)</span>
                <span class="font-bold text-slate-800">设备描述符 (Device Descriptor)</span>
              </div>
              <span class="text-purple-700 font-bold text-[11px]">
                VID: {{ descriptorTree.device.vendor_id }} | PID: {{ descriptorTree.device.product_id }}
              </span>
            </div>

            <div class="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px] text-slate-600 bg-purple-50/30 p-2.5 rounded-xl">
              <div>USB 规范版本: <strong class="text-slate-800">{{ descriptorTree.device.bcd_usb }}</strong></div>
              <div>设备类别代码: <strong class="text-slate-800">0x{{ descriptorTree.device.device_class.toString(16).padStart(2, '0').toUpperCase() }}</strong></div>
              <div>子类别: <strong class="text-slate-800">0x{{ descriptorTree.device.device_subclass.toString(16).padStart(2, '0').toUpperCase() }}</strong></div>
              <div>协议代码: <strong class="text-slate-800">0x{{ descriptorTree.device.device_protocol.toString(16).padStart(2, '0').toUpperCase() }}</strong></div>
              <div>EP0 最大包长: <strong class="text-slate-800">{{ descriptorTree.device.max_packet_size0 }} 字节</strong></div>
              <div>设备版本号: <strong class="text-slate-800">{{ descriptorTree.device.bcd_device }}</strong></div>
              <div>配置描述符数: <strong class="text-purple-700 font-bold">{{ descriptorTree.device.num_configurations }}</strong></div>
              <div>厂商/产品/串号: <span class="text-slate-500">i{{ descriptorTree.device.manufacturer_idx }}/i{{ descriptorTree.device.product_idx }}/i{{ descriptorTree.device.serial_idx }}</span></div>
            </div>
          </div>

          <!-- 2. Configuration Descriptors (二级节点) -->
          <div v-for="cfg in descriptorTree.configurations" :key="cfg.config_descriptor.config_value"
            class="bg-white border border-blue-200 rounded-2xl p-3.5 shadow-2xs flex flex-col gap-2.5 ml-4 border-l-4 border-l-blue-500">
            <div class="flex items-center justify-between border-b border-blue-100 pb-2">
              <div class="flex items-center gap-2">
                <span class="px-2 py-0.5 bg-blue-100 text-blue-800 rounded font-bold text-[10px]">CONFIG (0x02)</span>
                <span class="font-bold text-slate-800">配置描述符 #{{ cfg.config_descriptor.config_value }}</span>
              </div>
              <span class="text-blue-700 font-bold text-[11px]">
                总长度: {{ cfg.config_descriptor.total_length }} 字节 | 接口数: {{ cfg.config_descriptor.num_interfaces }}
              </span>
            </div>

            <div class="grid grid-cols-2 md:grid-cols-3 gap-2 text-[11px] text-slate-600 bg-blue-50/30 p-2 rounded-xl">
              <div>供电属性: <strong class="text-slate-800">0x{{ cfg.config_descriptor.attributes.toString(16).padStart(2, '0').toUpperCase() }} ({{ (cfg.config_descriptor.attributes & 0x40) ? '自供电' : '总线供电' }})</strong></div>
              <div>最大功耗: <strong class="text-blue-800">{{ cfg.config_descriptor.max_power_ma }} mA</strong></div>
              <div>配置索引: <span class="text-slate-500">i{{ cfg.config_descriptor.config_str_idx }}</span></div>
            </div>

            <!-- 3. Interface Descriptors (三级节点) -->
            <div v-for="iface in cfg.interfaces" :key="iface.interface_descriptor.interface_number"
              class="bg-white border border-emerald-200 rounded-xl p-3 shadow-2xs flex flex-col gap-2 ml-4 border-l-4 border-l-emerald-500">
              <div class="flex items-center justify-between border-b border-emerald-100 pb-1.5">
                <div class="flex items-center gap-2">
                  <span class="px-2 py-0.5 bg-emerald-100 text-emerald-800 rounded font-bold text-[10px]">INTERFACE (0x04)</span>
                  <span class="font-bold text-slate-800">接口 #{{ iface.interface_descriptor.interface_number }} (Alt {{ iface.interface_descriptor.alternate_setting }})</span>
                </div>
                <span class="text-emerald-700 font-bold text-[11px]">
                  端点数: {{ iface.interface_descriptor.num_endpoints }} | 类别: 0x{{ iface.interface_descriptor.interface_class.toString(16).padStart(2, '0').toUpperCase() }}
                </span>
              </div>

              <!-- 4. Endpoint Descriptors (四级叶节点) -->
              <div class="grid grid-cols-1 md:grid-cols-2 gap-2 mt-1">
                <div v-for="ep in iface.endpoints" :key="ep.endpoint_address"
                  class="bg-slate-50 border border-slate-200 rounded-lg p-2 flex items-center justify-between shadow-2xs">
                  <div class="flex items-center gap-2">
                    <span class="w-2 h-2 rounded-full" :class="ep.direction === 'IN' ? 'bg-sky-500' : 'bg-emerald-500'"></span>
                    <div>
                      <div class="font-bold text-slate-800 text-[11px]">
                        端点 0x{{ ep.endpoint_address.toString(16).padStart(2, '0').toUpperCase() }} [{{ ep.direction }}]
                      </div>
                      <div class="text-[9px] text-slate-500">
                        类型: {{ ep.transfer_type }} | 间隔: {{ ep.interval_ms }}ms
                      </div>
                    </div>
                  </div>
                  <div class="text-right">
                    <div class="font-bold text-[11px] text-slate-700">{{ ep.max_packet_size }} 字节</div>
                    <div class="text-[9px] text-slate-400">Max Packet</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- 底部操作 -->
      <div class="px-6 py-3 border-t border-slate-200/60 bg-white/40 flex items-center justify-end shrink-0">
        <button @click="$emit('close')" class="px-4 py-1.5 rounded-xl text-xs font-semibold text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer">
          关闭
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { invoke } from '@tauri-apps/api/core';

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

onMounted(() => {
  if (rawHex.value.trim()) {
    doParseTree();
  }
});
</script>
