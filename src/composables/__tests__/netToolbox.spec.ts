import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  formatLatencyBadge,
  parseEtherTypeHexInput,
  parsePortInput,
  useNetToolbox,
  validateCidrPrecheck,
  validateMacLookupInput,
} from '../useNetToolbox';

const invokeMock = vi.fn();

vi.mock('@tauri-apps/api/core', () => ({
  invoke: (cmd: string, args?: Record<string, unknown>) => invokeMock(cmd, args),
}));

describe('useNetToolbox pure validators & state machine', () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it('validates TCP/UDP ports strictly within 1..65535', () => {
    expect(parsePortInput(502)).toBe(502);
    expect(parsePortInput('443')).toBe(443);
    expect(parsePortInput(0)).toBeNull();
    expect(parsePortInput(65536)).toBeNull();
    expect(parsePortInput(-1)).toBeNull();
    expect(parsePortInput('abc')).toBeNull();
    expect(parsePortInput(80.5)).toBeNull();
  });

  it('parses EtherType hexadecimal inputs with and without 0x prefix', () => {
    expect(parseEtherTypeHexInput('0x88CC')).toBe(0x88cc);
    expect(parseEtherTypeHexInput('0800')).toBe(0x0800);
    expect(parseEtherTypeHexInput('ffff')).toBe(0xffff);
    expect(parseEtherTypeHexInput('0x10000')).toBeNull();
    expect(parseEtherTypeHexInput('zzzz')).toBeNull();
  });

  it('sanitizes MAC OUI strings cleanly and rejects malformed payloads', () => {
    expect(validateMacLookupInput('00:1b:1b:01:02:03')).toBe('001B1B010203');
    expect(validateMacLookupInput('00-1b-1b')).toBe('001B1B');
    expect(validateMacLookupInput('1234')).toBeNull();
    expect(validateMacLookupInput('00:1b:1b;rm -rf')).toBeNull();
  });

  it('prechecks CIDR inputs and formats latency badges properly', () => {
    expect(validateCidrPrecheck('192.168.10.55/24')).toBe(true);
    expect(validateCidrPrecheck('2001:db8::1/64')).toBe(true);
    expect(validateCidrPrecheck('')).toBe(false);
    expect(validateCidrPrecheck('192.168.1.1; cat /etc/passwd')).toBe(false);

    expect(formatLatencyBadge(12.345)).toBe('12.35 ms');
    expect(formatLatencyBadge(null)).toBe('TIMEOUT');
    expect(formatLatencyBadge(5, 100)).toBe('UNREACHABLE');
  });

  it('invokes calculate_subnet_info_cmd and auto-adjusts VLSM prefix safely', async () => {
    invokeMock.mockResolvedValueOnce({
      ip_version: 4,
      input_normalized: '10.10.0.1/28',
      prefix_len: 28,
      network_address: '10.10.0.0',
      broadcast_address: '10.10.0.15',
      netmask: '255.255.255.240',
      wildcard_mask: '0.0.0.15',
      first_usable_ip: '10.10.0.1',
      last_usable_ip: '10.10.0.14',
      total_addresses: '16',
      usable_hosts: '14',
      address_class: 'RFC 1918',
      binary_view: '00001010...',
      ptr_reverse_domain: '1.0.10.10.in-addr.arpa',
    });

    const box = useNetToolbox();
    box.subnetInput.value = '10.10.0.1/28';
    box.vlsmTargetPrefix.value = 26;
    await box.runSubnetCalc();

    expect(invokeMock).toHaveBeenCalledWith('calculate_subnet_info_cmd', {
      input: '10.10.0.1/28',
    });
    expect(box.subnetResult.value?.usable_hosts).toBe('14');
    // 因原 targetPrefix(26) <= 当前 /28，应自动上调为 /30
    expect(box.vlsmTargetPrefix.value).toBe(30);
  });

  it('blocks empty sandbox paths before invoking TFTP/HTTP file servers', async () => {
    const box = useNetToolbox();
    box.tftpRoot.value = '   ';
    await box.toggleTftpServer();
    expect(box.errorMessage.value).toContain('TFTP');
    expect(invokeMock).not.toHaveBeenCalled();

    box.httpServeRoot.value = '';
    await box.toggleHttpFileServer();
    expect(box.errorMessage.value).toContain('HTTP');
    expect(invokeMock).not.toHaveBeenCalled();
  });

  it('switches terminal protocol between Telnet (23) and SSH (22) and blocks unlinked send', async () => {
    const box = useNetToolbox();
    expect(box.terminalProtocol.value).toBe('Telnet');
    expect(box.terminalPort.value).toBe(23);

    box.switchTerminalProtocol('Ssh');
    expect(box.terminalProtocol.value).toBe('Ssh');
    expect(box.terminalPort.value).toBe(22);

    box.switchTerminalProtocol('Telnet');
    expect(box.terminalProtocol.value).toBe('Telnet');
    expect(box.terminalPort.value).toBe(23);

    // 未连接时阻断发送并给出友好提示
    await box.sendTerminalCommand('show version');
    expect(box.errorMessage.value).toContain('终端未连接');
    expect(invokeMock).not.toHaveBeenCalled();
  });
});
