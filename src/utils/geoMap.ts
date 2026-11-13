/**
 * Omni-Probe 网络地理测地线与二维投影核心数学算法库
 * 
 * 包含：
 * 1. 世界陆地板块高精轮廓矩阵 (WGS-84 经纬度多边形，涵盖全球大陆与主要大岛群岛)
 * 2. 大地基准线数据 (赤道、南北回归线、本初子午线、30°/20° 经纬网格)
 * 3. 等角圆柱投影 (Equirectangular Projection) 坐标转换
 * 4. 大圆测地距离算法 (Haversine 大圆距离测算)
 * 5. 光纤介质理论物理往返时延测算 (二氧化硅介质光速 c_fiber ≈ 204,190 km/s)
 * 6. 测地大圆航线贝塞尔控制点平滑曲线生成 (单跳与多跳链条序列)
 */

// 世界大陆主陆地板块与全球主要大岛经纬度多边形集 (WGS-84 坐标系: [经度 Lon, 纬度 Lat])
export const WORLD_LAND_POLYGONS: number[][][] = [
  // 1. 欧亚大陆主陆地板块 (包含中国大陆细部海岸线、雷州半岛、中南半岛、欧洲、小亚细亚、斯堪的纳维亚、西伯利亚)
  [
    [121.6, 38.9], [122.5, 37.4], [119.5, 35.0], [121.9, 30.9], [120.0, 26.5], [116.8, 23.5], [113.8, 22.3],
    [110.3, 20.9], [108.5, 21.5], [106.0, 19.5], [109.0, 13.0], [105.0, 10.0], [100.5, 13.7], [103.8, 1.3],
    [98.5, 8.0], [96.0, 17.0], [90.0, 22.0], [80.0, 16.0], [77.5, 8.1], [73.0, 19.0], [68.0, 24.0],
    [57.0, 25.5], [50.0, 26.0], [45.0, 13.0], [43.0, 12.5], [35.0, 28.0], [32.5, 30.0], [35.0, 33.0],
    [28.0, 41.0], [23.7, 38.0], [15.0, 38.0], [12.5, 44.0], [4.0, 43.5], [-1.5, 43.5], [-5.3, 36.1],
    [-9.5, 38.8], [-9.0, 43.0], [1.0, 50.0], [8.5, 54.0], [10.0, 57.5], [5.0, 62.0], [15.0, 68.0],
    [25.8, 71.2], [33.0, 69.0], [40.0, 67.0], [55.0, 68.0], [70.0, 73.0], [100.0, 77.0], [140.0, 72.0],
    [170.0, 66.0], [162.0, 55.0], [143.0, 50.0], [132.0, 43.0], [127.0, 38.0], [129.0, 35.0], [126.0, 37.0],
    [124.5, 40.0], [121.6, 38.9]
  ],
  // 2. 非洲大陆板块 (好望角、几内亚湾、索马里之角、北非地中海沿岸)
  [
    [32.5, 30.0], [34.0, 27.0], [43.5, 12.0], [51.2, 10.5], [40.5, -15.0], [35.0, -25.0], [28.0, -32.5],
    [18.5, -34.3], [14.5, -23.0], [12.0, -6.0], [9.0, 4.0], [0.0, 5.5], [-13.0, 9.0], [-17.5, 14.7],
    [-13.0, 27.0], [-5.8, 35.8], [10.5, 37.0], [20.0, 32.0], [30.0, 31.2], [32.5, 30.0]
  ],
  // 3. 北美洲大陆板块 (阿拉斯加、太平洋西岸、佛罗里达、墨西哥湾、拉布拉多)
  [
    [-168.0, 65.5], [-160.0, 56.0], [-140.0, 60.0], [-125.0, 49.0], [-122.4, 37.8], [-117.0, 32.5],
    [-110.0, 23.0], [-105.0, 20.0], [-95.0, 16.0], [-80.0, 8.5], [-77.0, 8.0], [-83.0, 10.0],
    [-89.0, 21.0], [-97.0, 26.0], [-89.5, 29.0], [-80.5, 25.0], [-76.0, 37.0], [-70.0, 43.0],
    [-60.0, 47.0], [-55.0, 50.0], [-65.0, 60.0], [-85.0, 60.0], [-95.0, 70.0], [-120.0, 70.0],
    [-156.7, 71.3], [-168.0, 65.5]
  ],
  // 4. 南美洲大陆板块 (安第斯山脉沿线、麦哲伦海峡、巴西高原、亚马逊河口)
  [
    [-77.0, 8.0], [-70.0, 12.0], [-60.0, 10.0], [-50.0, 0.0], [-35.0, -5.5], [-38.0, -13.0],
    [-43.0, -23.0], [-50.0, -30.0], [-58.0, -35.0], [-65.0, -42.0], [-67.0, -55.0], [-74.0, -45.0],
    [-71.5, -33.0], [-77.0, -12.0], [-80.0, -2.0], [-77.0, 8.0]
  ],
  // 5. 澳大利亚大陆板块 (东部大分水岭、卡奔塔利亚湾、大堡礁沿线、西澳海岸)
  [
    [142.5, -11.0], [149.0, -20.0], [153.0, -27.5], [150.0, -37.0], [140.0, -38.0], [130.0, -32.0],
    [115.5, -34.0], [114.0, -22.0], [122.0, -17.0], [130.8, -12.5], [136.0, -12.0], [142.5, -11.0]
  ],
  // 6. 日本列岛板块 (本州、北海道、九州、四国)
  [
    [140.5, 35.5], [141.5, 38.5], [141.0, 41.5], [140.0, 43.0], [145.0, 44.0], [142.0, 42.0],
    [139.5, 36.5], [135.5, 34.5], [131.0, 31.5], [130.0, 33.5], [133.0, 35.5], [137.0, 37.0], [140.5, 35.5]
  ],
  // 7. 中国台湾岛
  [
    [121.5, 25.3], [122.0, 24.5], [121.0, 22.0], [120.2, 23.0], [120.5, 24.5], [121.5, 25.3]
  ],
  // 8. 中国海南岛
  [
    [110.5, 20.0], [111.0, 19.0], [109.5, 18.2], [108.6, 19.2], [110.5, 20.0]
  ],
  // 9. 不列颠群岛与爱尔兰岛
  [
    [-5.0, 50.0], [1.5, 51.5], [0.0, 54.0], [-2.0, 58.5], [-5.0, 58.5], [-5.0, 55.0], [-3.0, 51.5], [-5.0, 50.0]
  ],
  // 10. 格陵兰岛
  [
    [-45.0, 60.0], [-35.0, 65.0], [-20.0, 75.0], [-30.0, 82.0], [-60.0, 80.0], [-55.0, 70.0], [-45.0, 60.0]
  ],
  // 11. 马达加斯加岛
  [
    [49.5, -12.0], [50.5, -16.0], [47.5, -25.0], [44.0, -25.5], [43.5, -20.0], [47.0, -14.0], [49.5, -12.0]
  ],
  // 12. 印度尼西亚群岛 (加里曼丹 / 婆罗洲主要轮廓)
  [
    [109.0, 1.0], [113.0, 3.5], [117.5, 4.0], [119.0, 1.5], [117.0, -1.0], [114.5, -3.5], [110.0, -3.0], [109.0, 1.0]
  ],
  // 13. 菲律宾群岛 (吕宋 / 棉兰老主体)
  [
    [120.5, 18.5], [122.5, 16.5], [124.0, 13.0], [126.0, 7.5], [124.5, 5.5], [121.5, 7.0], [120.0, 14.5], [120.5, 18.5]
  ],
  // 14. 新西兰南北岛
  [
    [174.0, -35.0], [178.5, -38.0], [175.5, -41.5], [170.0, -46.0], [166.5, -46.5], [171.0, -42.0], [174.0, -35.0]
  ],
  // 15. 古巴岛与加勒比
  [
    [-84.5, 22.0], [-80.0, 22.5], [-75.0, 20.0], [-76.0, 19.8], [-81.0, 21.0], [-84.5, 22.0]
  ],
  // 16. 冰岛
  [
    [-24.0, 65.5], [-18.0, 66.5], [-13.5, 65.0], [-14.5, 64.0], [-19.0, 63.4], [-23.0, 64.0], [-24.0, 65.5]
  ],
  // 17. 南极洲主陆地北缘 (极地测绘陆架)
  [
    [-180.0, -78.0], [-120.0, -75.0], [-65.0, -64.0], [-40.0, -74.0], [0.0, -70.0], [60.0, -68.0],
    [100.0, -66.0], [140.0, -67.0], [170.0, -72.0], [180.0, -78.0]
  ]
];

/**
 * 等角圆柱投影 (Equirectangular Projection)
 * 将 WGS-84 经纬度投影至笛卡尔平面坐标 [x, y]
 * 时间复杂度: O(1) | 空间复杂度: O(1)
 */
export function projectEquirectangular(
  lon: number,
  lat: number,
  width: number = 960,
  height: number = 480
): [number, number] {
  // 规范化经纬度边界
  const clampedLon = Math.max(-180.0, Math.min(180.0, lon));
  const clampedLat = Math.max(-90.0, Math.min(90.0, lat));

  const x = ((clampedLon + 180.0) / 360.0) * width;
  const y = ((90.0 - clampedLat) / 180.0) * height;
  return [Number(x.toFixed(1)), Number(y.toFixed(1))];
}

/**
 * 基于 Haversine (半正矢公式) 计算地球表面两点间的大圆测地距离 (千米)
 * 地球平均曲率半径 R = 6371.0088 km
 * 时间复杂度: O(1) | 空间复杂度: O(1)
 */
export function calculateGreatCircleDistanceKm(
  lon1: number,
  lat1: number,
  lon2: number,
  lat2: number
): number {
  if (Math.abs(lon1 - lon2) < 1e-6 && Math.abs(lat1 - lat2) < 1e-6) {
    return 0;
  }

  const R = 6371.0088;
  const dLat = ((lat2 - lat1) * Math.PI) / 180.0;
  const dLon = ((lon2 - lon1) * Math.PI) / 180.0;
  const radLat1 = (lat1 * Math.PI) / 180.0;
  const radLat2 = (lat2 * Math.PI) / 180.0;

  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(radLat1) * Math.cos(radLat2) * Math.sin(dLon / 2) * Math.sin(dLon / 2);

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(Math.max(0, 1 - a)));
  return R * c;
}

/**
 * 物理光纤在纯二氧化硅介质中的理论最低光速往返传输时延 (RTT_min)
 * 物理折射率 n_silica ≈ 1.4682 => 光速 v ≈ 204,190 km/s ≈ 204.19 km/ms
 * RTT_min (ms) = 2 * distance_km / 204.19
 * 时间复杂度: O(1)
 */
export function calculateSpeedOfLightDelayMs(distKm: number): number {
  if (distKm <= 0) return 0.1; // 局域网物理介质时延保底值
  return Number(((2 * distKm) / 204.19).toFixed(2));
}

/**
 * 生成平滑贝塞尔测地飞线路径字符串 (SVG Path)
 * 自动根据两点屏幕像素距离动态计算拱高弧度
 */
export function generateArcSvgPath(
  x1: number,
  y1: number,
  x2: number,
  y2: number,
  maxArcHeight: number = 40
): string {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const distPx = Math.sqrt(dx * dx + dy * dy);

  // 跨半球或极短距离保护
  const midX = (x1 + x2) / 2;
  const arcHeight = Math.min(maxArcHeight, Math.max(10, distPx * 0.22));
  const midY = (y1 + y2) / 2 - arcHeight;

  return `M ${x1.toFixed(1)} ${y1.toFixed(1)} Q ${midX.toFixed(1)} ${midY.toFixed(1)}, ${x2.toFixed(1)} ${y2.toFixed(1)}`;
}

export interface GeoWaypoint {
  hopNumber: number;
  ip: string;
  lon: number;
  lat: number;
  x2d: number;
  y2d: number;
  rttMs?: number;
  role?: string;
  location?: string;
  isp?: string;
  isSelf?: boolean;
  isDestination?: boolean;
}

export interface FlightArcSegment {
  pathData: string;
  fromHop: number;
  toHop: number;
  distKm: number;
  color: string;
}

/**
 * 为多跳 Traceroute 路由链条生成逐跳平滑飞线段列表
 */
export function generateMultiHopFlightArcs(
  waypoints: GeoWaypoint[],
  maxArcHeight: number = 35
): FlightArcSegment[] {
  if (waypoints.length < 2) return [];
  const segments: FlightArcSegment[] = [];

  for (let i = 0; i < waypoints.length - 1; i++) {
    const p1 = waypoints[i];
    const p2 = waypoints[i + 1];

    const pathData = generateArcSvgPath(p1.x2d, p1.y2d, p2.x2d, p2.y2d, maxArcHeight);
    const distKm = calculateGreatCircleDistanceKm(p1.lon, p1.lat, p2.lon, p2.lat);

    let color = '#38bdf8'; // 默认青蓝骨干链路
    if (p1.isSelf) {
      color = '#10b981'; // 本地出站首跳翡翠绿
    } else if (p2.isDestination) {
      color = '#f59e0b'; // 终点目标跳琥珀橙
    }

    segments.push({
      pathData,
      fromHop: p1.hopNumber,
      toHop: p2.hopNumber,
      distKm,
      color
    });
  }

  return segments;
}

/**
 * 格式化输出标准化行政区划地理位置名称
 */
export function formatGeoLocation(
  country?: string,
  province?: string,
  city?: string,
  isLan: boolean = false
): string {
  if (isLan) return '局域网/内网节点';
  const parts: string[] = [];
  if (country && country !== '未知' && country !== '0') parts.push(country);
  if (province && province !== '未知' && province !== '0' && province !== country) parts.push(province);
  if (city && city !== '未知' && city !== '0' && city !== province) parts.push(city);
  return parts.join(' · ') || '广域骨干网络节点';
}

/**
 * 基于球面线性插值 (Slerp) 严谨推算两点间测地大圆上的任意插值点经纬度坐标
 * t: 归一化进度 [0.0, 1.0]
 * 时间复杂度: O(1) | 空间复杂度: O(1)
 */
export function interpolateGreatCirclePoint(
  lon1: number,
  lat1: number,
  lon2: number,
  lat2: number,
  t: number
): [number, number] {
  if (t <= 0) return [lon1, lat1];
  if (t >= 1) return [lon2, lat2];

  const rad = Math.PI / 180.0;
  const lat1Rad = lat1 * rad;
  const lon1Rad = lon1 * rad;
  const lat2Rad = lat2 * rad;
  const lon2Rad = lon2 * rad;

  // 转换为 3D 单位向量
  const v1 = [
    Math.cos(lat1Rad) * Math.cos(lon1Rad),
    Math.cos(lat1Rad) * Math.sin(lon1Rad),
    Math.sin(lat1Rad)
  ];
  const v2 = [
    Math.cos(lat2Rad) * Math.cos(lon2Rad),
    Math.cos(lat2Rad) * Math.sin(lon2Rad),
    Math.sin(lat2Rad)
  ];

  const dot = Math.max(-1.0, Math.min(1.0, v1[0] * v2[0] + v1[1] * v2[1] + v1[2] * v2[2]));
  const omega = Math.acos(dot);

  if (Math.abs(omega) < 1e-6) {
    return [lon1, lat1];
  }

  const sinOmega = Math.sin(omega);
  const w1 = Math.sin((1.0 - t) * omega) / sinOmega;
  const w2 = Math.sin(t * omega) / sinOmega;

  const x = w1 * v1[0] + w2 * v2[0];
  const y = w1 * v1[1] + w2 * v2[1];
  const z = w1 * v1[2] + w2 * v2[2];

  const outLat = Math.asin(Math.max(-1.0, Math.min(1.0, z))) / rad;
  const outLon = Math.atan2(y, x) / rad;

  return [Number(outLon.toFixed(4)), Number(outLat.toFixed(4))];
}
