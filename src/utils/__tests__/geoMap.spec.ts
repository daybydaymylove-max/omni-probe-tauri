import { describe, it, expect } from 'vitest';
import {
  projectEquirectangular,
  calculateGreatCircleDistanceKm,
  calculateSpeedOfLightDelayMs,
  generateArcSvgPath,
  generateMultiHopFlightArcs,
  interpolateGreatCirclePoint,
  formatGeoLocation,
  WORLD_LAND_POLYGONS,
  type GeoWaypoint
} from '../geoMap';

describe('geoMap 核心测地与投影算法套件', () => {
  describe('WORLD_LAND_POLYGONS 高精度大陆板块与群岛覆盖性', () => {
    it('应包含全球主要大陆与重点大岛群岛板块 (不少于 15 组独立多边形)', () => {
      expect(WORLD_LAND_POLYGONS.length).toBeGreaterThanOrEqual(15);
      // 每个多边形至少 4 个顶点构成闭合几何体
      for (const poly of WORLD_LAND_POLYGONS) {
        expect(poly.length).toBeGreaterThanOrEqual(4);
      }
    });
  });

  describe('projectEquirectangular 等角圆柱投影测试', () => {
    it('常规用例: 本初子午线与赤道交点 (0, 0) 应投影为中心点 (480, 240)', () => {
      // 时间复杂度 O(1), 空间复杂度 O(1)
      const [x, y] = projectEquirectangular(0, 0, 960, 480);
      expect(x).toBe(480);
      expect(y).toBe(240);
    });

    it('极限用例 1: 边界经纬度 (-180, 90) 与 (180, -90)', () => {
      const [xMin, yMin] = projectEquirectangular(-180, 90, 960, 480);
      expect(xMin).toBe(0);
      expect(yMin).toBe(0);

      const [xMax, yMax] = projectEquirectangular(180, -90, 960, 480);
      expect(xMax).toBe(960);
      expect(yMax).toBe(480);
    });

    it('极限用例 2: 越界数据输入防御 (超限截断保护)', () => {
      const [xOver, yOver] = projectEquirectangular(250, 120, 960, 480);
      expect(xOver).toBe(960);
      expect(yOver).toBe(0);
    });
  });

  describe('calculateGreatCircleDistanceKm 大圆测地距离 (Haversine) 测试', () => {
    it('常规用例: 北京 (116.4, 39.9) 至 深圳 (114.1, 22.5) 距离约为 1900~2000 km', () => {
      // 时间复杂度 O(1)
      const dist = calculateGreatCircleDistanceKm(116.4, 39.9, 114.1, 22.5);
      expect(dist).toBeGreaterThan(1900);
      expect(dist).toBeLessThan(2000);
    });

    it('极限用例 1: 同一点距离应精确为 0 km', () => {
      const dist = calculateGreatCircleDistanceKm(114.05, 22.55, 114.05, 22.55);
      expect(dist).toBe(0);
    });

    it('极限用例 2: 对跖点 (赤道正相对两侧 -180° 与 0°) 距离应接近半个地球赤道长 (~20000 km)', () => {
      const dist = calculateGreatCircleDistanceKm(-180, 0, 0, 0);
      expect(dist).toBeGreaterThan(19900);
      expect(dist).toBeLessThan(20100);
    });
  });

  describe('calculateSpeedOfLightDelayMs 光速极限时延测试', () => {
    it('常规用例: 2041.9 km 物理距离理论极限 RTT 应为 ~20.00 ms', () => {
      const delay = calculateSpeedOfLightDelayMs(2041.9);
      expect(delay).toBe(20.0);
    });

    it('极限用例: 零距离局域网输入应返回保底时延', () => {
      const delay = calculateSpeedOfLightDelayMs(0);
      expect(delay).toBe(0.1);
    });
  });

  describe('generateArcSvgPath 与 generateMultiHopFlightArcs 测试', () => {
    it('SVG 贝塞尔飞线路径格式应合法', () => {
      const path = generateArcSvgPath(100, 200, 500, 200, 40);
      expect(path).toContain('M 100.0 200.0 Q 300.0');
    });

    it('多跳路由航路链条生成验证', () => {
      const waypoints: GeoWaypoint[] = [
        { hopNumber: 0, ip: '192.168.1.100', lon: 114.05, lat: 22.55, x2d: 784, y2d: 180, isSelf: true },
        { hopNumber: 1, ip: '202.96.128.86', lon: 113.26, lat: 23.13, x2d: 782, y2d: 178 },
        { hopNumber: 2, ip: '8.8.8.8', lon: -122.08, lat: 37.38, x2d: 154, y2d: 140, isDestination: true }
      ];

      const arcs = generateMultiHopFlightArcs(waypoints, 30);
      expect(arcs.length).toBe(2);
      expect(arcs[0].fromHop).toBe(0);
      expect(arcs[0].toHop).toBe(1);
      expect(arcs[0].color).toBe('#10b981'); // 首跳源点绿
      expect(arcs[1].fromHop).toBe(1);
      expect(arcs[1].toHop).toBe(2);
      expect(arcs[1].color).toBe('#f59e0b'); // 终跳目标橙
    });

    it('内网与未知地理位置标准化输出', () => {
      expect(formatGeoLocation('中国', '广东', '深圳', false)).toBe('中国 · 广东 · 深圳');
      expect(formatGeoLocation('未知', '未知', '未知', false)).toBe('广域骨干网络节点');
      expect(formatGeoLocation('', '', '', true)).toBe('局域网/内网节点');
    });

    it('interpolateGreatCirclePoint 球面大圆航线空间插值准确性', () => {
      // 0 与 1 边界
      const p0 = interpolateGreatCirclePoint(114.0, 22.0, 116.0, 40.0, 0.0);
      expect(p0[0]).toBe(114.0);
      expect(p0[1]).toBe(22.0);

      const p1 = interpolateGreatCirclePoint(114.0, 22.0, 116.0, 40.0, 1.0);
      expect(p1[0]).toBe(116.0);
      expect(p1[1]).toBe(40.0);

      // 中点插值
      const mid = interpolateGreatCirclePoint(114.0, 22.0, 116.0, 40.0, 0.5);
      expect(mid[0]).toBeGreaterThan(114.0);
      expect(mid[0]).toBeLessThan(116.0);
      expect(mid[1]).toBeGreaterThan(22.0);
      expect(mid[1]).toBeLessThan(40.0);
    });
  });
});
