import { useEffect, useRef, useState } from "react";
import * as THREE from "three";
import clsx from "clsx";
import landmask from "./landmask.json";
import { fmtNumber, riskColor } from "../../lib/format";
import { palette, useTheme } from "../../lib/theme";
import { SignalMap } from "../charts";

export interface GlobePoint {
  country?: string;
  code?: string;
  count: number;
  lat: number;
  lon: number;
  records?: number;
  maxRisk?: number;
  classes?: string[];
}

/* The globe and the flat map have to describe the same Earth, so both use
   SignalMap's equirectangular grid and the same land mask. */
const COLS = 72;
const ROWS = 36;
const LAT_TOP = 78;
const LAT_BOTTOM = -56;
const LAT_SPAN = LAT_TOP - LAT_BOTTOM;

const DEFAULT_DISTANCE = 3.05;
const MIN_DISTANCE = 2.2;
const MAX_DISTANCE = 4.5;
const POINT_SCALE = 300;
const SPIN_RAD_PER_SEC = 0.075;
const IDLE_BEFORE_SPIN = 1100;
const MAX_PITCH = 1.05;
/* Share of the shorter panel edge the globe body should occupy. */
const FRAME_FILL = 0.74;
/* A pulse has to be earned by recorded volume or by a recorded score crossing
   the engine's critical band — never by an implied activity feed. */
const CRITICAL_BAND = 75;

function latLonToVector(lat: number, lon: number, radius: number): THREE.Vector3 {
  const phi = ((90 - lat) * Math.PI) / 180;
  const theta = ((lon + 180) * Math.PI) / 180;
  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta),
  );
}

function cellToLatLon(gridX: number, gridY: number): [number, number] {
  return [LAT_TOP - (gridY / ROWS) * LAT_SPAN, (gridX / COLS) * 360 - 180];
}

/**
 * Face the centre of the recorded locations rather than a fixed longitude, so
 * the opening frame is never an empty stretch of ocean. Only the stored
 * coordinates decide this; the globe adds no geography of its own.
 */
function homeView(points: GlobePoint[]): { yaw: number; pitch: number } {
  const centre = new THREE.Vector3();
  for (const point of points) centre.add(latLonToVector(point.lat, point.lon, 1));
  if (centre.lengthSq() < 1e-6) return { yaw: 0, pitch: -0.2 };
  centre.normalize();
  return {
    yaw: Math.atan2(-centre.x, centre.z),
    pitch: Math.max(-0.42, Math.min(0.42, Math.atan2(centre.y, Math.hypot(centre.x, centre.z)) * 0.8)),
  };
}

/**
 * Land is the same 5° mask the flat map uses, subdivided and jittered inside
 * each cell so the field reads as fine particles rather than a lattice. The
 * keep-test is a hash of the cell, not Math.random, so the surface is identical
 * on every rebuild, and thinning towards high latitudes compensates for the
 * equirectangular grid over-sampling there.
 */
function buildLandField(subdivide: number): number[] {
  const positions: number[] = [];
  const rows = landmask as string[];
  for (let y = 0; y < Math.min(ROWS, rows.length); y++) {
    const row = rows[y];
    for (let x = 0; x < Math.min(COLS, row.length); x++) {
      if (row[x] !== "#") continue;
      for (let sy = 0; sy < subdivide; sy++) {
        for (let sx = 0; sx < subdivide; sx++) {
          const jitterX = (((x * 11 + y * 17 + sx * 5 + sy * 7) % 9) / 9 - 0.5) * 0.9;
          const jitterY = (((x * 13 + y * 19 + sx * 7 + sy * 3) % 9) / 9 - 0.5) * 0.9;
          const [lat, lon] = cellToLatLon(
            x + (sx + 0.5 + jitterX) / subdivide,
            y + (sy + 0.5 + jitterY) / subdivide,
          );
          const keep = ((x * 7 + y * 13 + sx * 3 + sy * 11) % 29) / 29;
          if (keep > 0.34 + 0.66 * Math.cos((lat * Math.PI) / 180)) continue;
          const v = latLonToVector(lat, lon, 1.004);
          positions.push(v.x, v.y, v.z);
        }
      }
    }
  }
  return positions;
}

function mix(from: THREE.Color, to: THREE.Color, t: number): THREE.Color {
  return from.clone().lerp(to, Math.max(0, Math.min(1, t)));
}

function canvasTexture(size: number, draw: (ctx: CanvasRenderingContext2D, s: number) => void): THREE.Texture {
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d");
  if (ctx) draw(ctx, size);
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

function dotTexture(color: string, softness: number, size = 64): THREE.Texture {
  return canvasTexture(size, (ctx, s) => {
    const half = s / 2;
    const gradient = ctx.createRadialGradient(half, half, 0, half, half, half);
    gradient.addColorStop(0, color);
    gradient.addColorStop(softness, color);
    /* Several intermediate stops keep a very soft falloff smooth once the sprite
       is stretched across the panel; a two-stop gradient bands visibly. */
    const steps = 8;
    for (let i = 1; i <= steps; i++) {
      const t = softness + (i / steps) * (1 - softness);
      const alpha = (1 - (i - 1) / steps) ** 1.8;
      gradient.addColorStop(t, withAlpha(color, alpha));
    }
    gradient.addColorStop(1, "rgba(0,0,0,0)");
    ctx.fillStyle = gradient;
    ctx.beginPath();
    ctx.arc(half, half, half, 0, Math.PI * 2);
    ctx.fill();
  });
}

function withAlpha(rgba: string, scale: number): string {
  const match = rgba.match(/rgba?\(([^)]+)\)/);
  if (!match) return rgba;
  const [r, g, b, a = "1"] = match[1].split(",").map((part) => part.trim());
  return `rgba(${r},${g},${b},${(Number(a) * scale).toFixed(3)})`;
}

function ringTexture(color: string, width: number): THREE.Texture {
  return canvasTexture(128, (ctx, size) => {
    ctx.strokeStyle = color;
    ctx.lineWidth = width;
    ctx.beginPath();
    ctx.arc(size / 2, size / 2, size * 0.42, 0, Math.PI * 2);
    ctx.stroke();
  });
}

const POINT_VERTEX = `
  attribute vec3 aColor;
  attribute float aSize;
  attribute float aPhase;
  uniform float uPixelRatio;
  uniform float uTime;
  uniform float uOpacity;
  varying vec3 vColor;
  varying float vAlpha;
  void main() {
    float twinkle = 0.9 + 0.1 * sin(uTime * 0.85 + aPhase);
    vColor = aColor;
    vAlpha = uOpacity * twinkle;
    vec4 mv = modelViewMatrix * vec4(position, 1.0);
    gl_PointSize = aSize * uPixelRatio * (${POINT_SCALE.toFixed(1)} / -mv.z);
    gl_Position = projectionMatrix * mv;
  }
`;

const LAND_FRAGMENT = `
  varying vec3 vColor;
  varying float vAlpha;
  void main() {
    float d = length(gl_PointCoord - vec2(0.5));
    if (d > 0.5) discard;
    float edge = 1.0 - smoothstep(0.26, 0.5, d);
    gl_FragColor = vec4(vColor, edge * vAlpha);
    #include <colorspace_fragment>
  }
`;

const MARKER_FRAGMENT = `
  varying vec3 vColor;
  varying float vAlpha;
  void main() {
    float d = length(gl_PointCoord - vec2(0.5));
    if (d > 0.5) discard;
    float core = 1.0 - smoothstep(0.14, 0.32, d);
    float rim = 1.0 - smoothstep(0.3, 0.5, d);
    gl_FragColor = vec4(vColor, core * 0.95 + rim * 0.32 * vAlpha);
    #include <colorspace_fragment>
  }
`;

/* The shell is painted, not lit: a fixed key direction gives the sphere its
   volume while the globe turns underneath it, and it stays opaque so the
   far half of the particle field is hidden. */
const SEA_VERTEX = `
  varying vec3 vWorldNormal;
  varying vec3 vViewDir;
  void main() {
    vec4 world = modelMatrix * vec4(position, 1.0);
    vWorldNormal = normalize(mat3(modelMatrix) * normal);
    vViewDir = normalize(cameraPosition - world.xyz);
    gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
  }
`;

const SEA_FRAGMENT = `
  uniform vec3 uLit;
  uniform vec3 uShade;
  uniform vec3 uKey;
  varying vec3 vWorldNormal;
  varying vec3 vViewDir;
  void main() {
    float lambert = dot(normalize(vWorldNormal), normalize(uKey)) * 0.5 + 0.5;
    vec3 base = mix(uShade, uLit, smoothstep(0.1, 0.92, lambert));
    float limb = 1.0 - abs(dot(normalize(vWorldNormal), normalize(vViewDir)));
    base *= 1.0 - 0.16 * pow(limb, 2.3);
    gl_FragColor = vec4(base, 1.0);
    #include <colorspace_fragment>
  }
`;

export function ThreatGlobe({
  points,
  height = 500,
  className,
  selected,
  onSelect,
  labels = true,
  mode = "markers",
  pulse = true,
  reducedMotion = false,
}: {
  points: GlobePoint[];
  height?: number | string;
  className?: string;
  selected?: string | null;
  onSelect?: (code: string) => void;
  labels?: boolean;
  mode?: "markers" | "density";
  pulse?: boolean;
  reducedMotion?: boolean;
}) {
  const { mode: themeMode } = useTheme();
  const hostRef = useRef<HTMLDivElement>(null);
  const canvasHostRef = useRef<HTMLDivElement>(null);
  const tipRef = useRef<HTMLDivElement>(null);
  const [zoomLabel, setZoomLabel] = useState(1);
  const [hovered, setHovered] = useState<string | null>(null);
  const [webglOff, setWebglOff] = useState(false);

  const liveRef = useRef({ points, selected, labels, mode, pulse, onSelect });
  liveRef.current = { points, selected, labels, mode, pulse, onSelect };
  const hoverRef = useRef<string | null>(null);
  const viewRef = useRef({ ...homeView(points), distance: DEFAULT_DISTANCE, touched: 0 });
  const apiRef = useRef<{ zoomBy: (factor: number) => void; reset: () => void } | null>(null);

  const signature = points
    .map((point) => `${point.code}:${point.count}:${point.lat.toFixed(2)}:${point.lon.toFixed(2)}`)
    .join("|");

  useEffect(() => {
    if (webglOff) return;
    const host = hostRef.current;
    const canvasHost = canvasHostRef.current;
    if (!host || !canvasHost) return;

    const tokens = palette();
    const dark = themeMode === "dark";
    const blending = dark ? THREE.AdditiveBlending : THREE.NormalBlending;
    const deepColor = new THREE.Color(dark ? tokens.pulse : "#0b3f6d");
    const accentColor = new THREE.Color(dark ? tokens.crystal : "#0a7fb0");

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 40);
    camera.position.set(0, 0, viewRef.current.distance);

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: "high-performance" });
    } catch {
      setWebglOff(true);
      return;
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    renderer.setClearColor(0x000000, 0);
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    renderer.domElement.style.width = "100%";
    renderer.domElement.style.height = "100%";
    renderer.domElement.style.display = "block";
    canvasHost.appendChild(renderer.domElement);

    const globe = new THREE.Group();
    scene.add(globe);

    /* The shell does two jobs: it gives the globe its icy body, and it hides the
       far side of the particle field, which is what makes the dots read as a
       sphere rather than a disc of points. */
    const seaLit = new THREE.Color(dark ? tokens.mapMid : "#f7fbff");
    const seaShade = dark ? seaLit.clone().multiplyScalar(0.34) : new THREE.Color("#c2d7ec");
    const ocean = new THREE.Mesh(
      new THREE.SphereGeometry(0.998, 64, 48),
      new THREE.ShaderMaterial({
        vertexShader: SEA_VERTEX,
        fragmentShader: SEA_FRAGMENT,
        uniforms: {
          uLit: { value: seaLit },
          uShade: { value: seaShade },
          uKey: { value: new THREE.Vector3(2.4, 1.6, 3.2).normalize() },
        },
      }),
    );
    globe.add(ocean);

    const glowMap = dotTexture(dark ? "rgba(73,184,255,0.3)" : "rgba(28,110,180,0.16)", 0.42, 256);
    const glow = new THREE.Sprite(
      new THREE.SpriteMaterial({
        map: glowMap,
        transparent: true,
        depthWrite: false,
        depthTest: false,
        blending: dark ? THREE.AdditiveBlending : THREE.NormalBlending,
      }),
    );
    glow.scale.setScalar(3.2);
    glow.renderOrder = -2;
    scene.add(glow);

    const graticulePositions: number[] = [];
    const addPolyline = (line: THREE.Vector3[]) => {
      for (let i = 0; i < line.length - 1; i++) {
        graticulePositions.push(line[i].x, line[i].y, line[i].z, line[i + 1].x, line[i + 1].y, line[i + 1].z);
      }
    };
    for (let lat = -60; lat <= 60; lat += 30) {
      const line: THREE.Vector3[] = [];
      for (let i = 0; i <= 120; i++) line.push(latLonToVector(lat, (i / 120) * 360 - 180, 1.0006));
      addPolyline(line);
    }
    for (let lon = -180; lon < 180; lon += 30) {
      const line: THREE.Vector3[] = [];
      for (let i = 0; i <= 96; i++) line.push(latLonToVector(90 - (i / 96) * 180, lon, 1.0006));
      addPolyline(line);
    }
    const graticuleMaterial = new THREE.LineBasicMaterial({
      color: new THREE.Color(dark ? tokens.pulse : "#1d5f95"),
      transparent: true,
      opacity: dark ? 0.1 : 0.12,
    });
    const graticule = new THREE.LineSegments(
      new THREE.BufferGeometry().setAttribute("position", new THREE.Float32BufferAttribute(graticulePositions, 3)),
      graticuleMaterial,
    );
    globe.add(graticule);

    const landPositions = buildLandField(4);
    const landCount = landPositions.length / 3;
    const landColors = new Float32Array(landCount * 3);
    const landSizes = new Float32Array(landCount);
    const landPhases = new Float32Array(landCount);
    const paint = new THREE.Color();
    for (let i = 0; i < landCount; i++) {
      const northness = Math.abs(landPositions[i * 3 + 1]);
      paint.copy(mix(accentColor, deepColor, 0.25 + northness * 0.7));
      landColors[i * 3] = paint.r;
      landColors[i * 3 + 1] = paint.g;
      landColors[i * 3 + 2] = paint.b;
      landSizes[i] = (dark ? 1.55 : 1.75 + (i % 11 === 0 ? 0.35 : 0)) * (DEFAULT_DISTANCE / POINT_SCALE);
      landPhases[i] = (i % 19) * 0.33;
    }
    const landMaterial = new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      blending,
      uniforms: {
        uPixelRatio: { value: renderer.getPixelRatio() },
        uTime: { value: 0 },
        uOpacity: { value: dark ? 0.9 : 0.82 },
      },
      vertexShader: POINT_VERTEX,
      fragmentShader: LAND_FRAGMENT,
    });
    const land = new THREE.Points(
      (() => {
        const geometry = new THREE.BufferGeometry();
        geometry.setAttribute("position", new THREE.BufferAttribute(new Float32Array(landPositions), 3));
        geometry.setAttribute("aColor", new THREE.BufferAttribute(landColors, 3));
        geometry.setAttribute("aSize", new THREE.BufferAttribute(landSizes, 1));
        geometry.setAttribute("aPhase", new THREE.BufferAttribute(landPhases, 1));
        return geometry;
      })(),
      landMaterial,
    );
    globe.add(land);

    const atmosphereMaterial = new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      side: THREE.BackSide,
      blending,
      uniforms: {
        uColor: { value: new THREE.Color(dark ? tokens.ion : "#2f7fc0") },
        uStrength: { value: dark ? 0.5 : 0.3 },
      },
      vertexShader: `
        varying vec3 vNormal;
        varying vec3 vView;
        void main() {
          vNormal = normalize(normalMatrix * normal);
          vec4 mv = modelViewMatrix * vec4(position, 1.0);
          vView = normalize(-mv.xyz);
          gl_Position = projectionMatrix * mv;
        }
      `,
      fragmentShader: `
        uniform vec3 uColor;
        uniform float uStrength;
        varying vec3 vNormal;
        varying vec3 vView;
        void main() {
          float rim = pow(1.0 - abs(dot(vNormal, vView)), 3.0);
          gl_FragColor = vec4(uColor, rim * uStrength);
          #include <colorspace_fragment>
        }
      `,
    });
    const atmosphere = new THREE.Mesh(new THREE.SphereGeometry(1.062, 48, 32), atmosphereMaterial);
    scene.add(atmosphere);

    const build = liveRef.current.points;
    const maxCount = Math.max(1, ...build.map((point) => point.count));
    const markerLocal: THREE.Vector3[] = [];
    const markerPositions = new Float32Array(build.length * 3);
    const markerColors = new Float32Array(build.length * 3);
    const markerSizes = new Float32Array(build.length);
    const haloSizes = new Float32Array(build.length);
    const markerPhases = new Float32Array(build.length);
    build.forEach((point, index) => {
      const v = latLonToVector(point.lat, point.lon, 1.014);
      markerLocal.push(v);
      markerPositions.set([v.x, v.y, v.z], index * 3);
      const intensity = Math.min(1, point.count / maxCount);
      const color = mix(deepColor, accentColor, 0.3 + intensity * 0.7);
      markerColors.set([color.r, color.g, color.b], index * 3);
      /* Area, not radius, carries the count — the same encoding the legend states. */
      markerSizes[index] = (4.6 + Math.sqrt(intensity) * 7.6) * (DEFAULT_DISTANCE / POINT_SCALE);
      haloSizes[index] = (13 + Math.sqrt(intensity) * 26) * (DEFAULT_DISTANCE / POINT_SCALE);
      markerPhases[index] = index * 0.8;
    });
    const markerGeometry = new THREE.BufferGeometry();
    markerGeometry.setAttribute("position", new THREE.BufferAttribute(markerPositions, 3));
    markerGeometry.setAttribute("aColor", new THREE.BufferAttribute(markerColors, 3));
    markerGeometry.setAttribute("aSize", new THREE.BufferAttribute(markerSizes, 1));
    markerGeometry.setAttribute("aPhase", new THREE.BufferAttribute(markerPhases, 1));
    const markerMaterial = new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      blending,
      uniforms: {
        uPixelRatio: { value: renderer.getPixelRatio() },
        uTime: { value: 0 },
        uOpacity: { value: 1 },
      },
      vertexShader: POINT_VERTEX,
      fragmentShader: MARKER_FRAGMENT,
    });
    const markers = new THREE.Points(markerGeometry, markerMaterial);
    markers.renderOrder = 3;
    globe.add(markers);

    const haloGeometry = new THREE.BufferGeometry();
    haloGeometry.setAttribute("position", new THREE.BufferAttribute(markerPositions, 3));
    haloGeometry.setAttribute("aColor", new THREE.BufferAttribute(markerColors, 3));
    haloGeometry.setAttribute("aSize", new THREE.BufferAttribute(haloSizes, 1));
    haloGeometry.setAttribute("aPhase", new THREE.BufferAttribute(markerPhases, 1));
    const haloMaterial = new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      blending,
      uniforms: {
        uPixelRatio: { value: renderer.getPixelRatio() },
        uTime: { value: 0 },
        uOpacity: { value: 0.22 },
      },
      vertexShader: POINT_VERTEX,
      fragmentShader: LAND_FRAGMENT,
    });
    const halos = new THREE.Points(haloGeometry, haloMaterial);
    halos.renderOrder = 2;
    globe.add(halos);

    const pulseMap = ringTexture(dark ? "rgba(150,228,255,0.9)" : "rgba(12,72,128,0.8)", 5);
    /* Rings are sized in screen pixels and converted to world units per frame,
       so a pulse stays a halo around its own marker at any zoom level. */
    const pulsing: Array<{ sprite: THREE.Sprite; basePx: number; phase: number }> = [];
    build.forEach((point, index) => {
      if (!(point.count >= maxCount * 0.55 || (point.maxRisk ?? 0) >= CRITICAL_BAND)) return;
      const sprite = new THREE.Sprite(
        new THREE.SpriteMaterial({ map: pulseMap, transparent: true, depthWrite: false, blending }),
      );
      sprite.position.copy(markerLocal[index]).multiplyScalar(1.004);
      sprite.renderOrder = 4;
      globe.add(sprite);
      pulsing.push({ sprite, basePx: markerSizes[index] * POINT_SCALE, phase: index * 0.9 });
    });

    const selectionMap = ringTexture(dark ? "rgba(214,244,255,0.95)" : "rgba(9,44,82,0.9)", 6);
    const selectionRing = new THREE.Sprite(
      new THREE.SpriteMaterial({
        map: selectionMap,
        transparent: true,
        depthWrite: false,
        depthTest: false,
        blending: THREE.NormalBlending,
        opacity: 0.95,
      }),
    );
    selectionRing.visible = false;
    selectionRing.renderOrder = 6;
    globe.add(selectionRing);

    const arcMaterial = new THREE.LineBasicMaterial({
      color: new THREE.Color(dark ? tokens.ion : "#1f6ea8"),
      transparent: true,
      opacity: dark ? 0.24 : 0.2,
      blending,
      depthWrite: false,
    });
    const arcPositions: number[] = [];
    for (let i = 0; i < Math.min(build.length, 9) - 1; i++) {
      const start = latLonToVector(build[i].lat, build[i].lon, 1).normalize();
      const end = latLonToVector(build[i + 1].lat, build[i + 1].lon, 1).normalize();
      const angle = start.angleTo(end);
      if (angle < 0.12 || angle > Math.PI - 0.12) continue;
      let previous: THREE.Vector3 | null = null;
      for (let s = 0; s <= 44; s++) {
        const t = s / 44;
        const c1 = Math.sin((1 - t) * angle) / Math.sin(angle);
        const c2 = Math.sin(t * angle) / Math.sin(angle);
        const dir = start.clone().multiplyScalar(c1).add(end.clone().multiplyScalar(c2)).normalize();
        const current = dir.multiplyScalar(1.016 + Math.sin(t * Math.PI) * Math.min(0.07, angle * 0.04));
        if (previous) arcPositions.push(previous.x, previous.y, previous.z, current.x, current.y, current.z);
        previous = current;
      }
    }
    const arcs = new THREE.LineSegments(
      new THREE.BufferGeometry().setAttribute("position", new THREE.Float32BufferAttribute(arcPositions, 3)),
      arcMaterial,
    );
    arcs.renderOrder = 1;
    globe.add(arcs);

    const labelNodes = new Map<string, HTMLElement>();
    host.querySelectorAll<HTMLElement>(".globe-label").forEach((node) => {
      const code = node.dataset.code || "";
      if (code) labelNodes.set(code, node);
    });

    let width = host.clientWidth || 520;
    let panelHeight = host.clientHeight || 520;
    const resize = () => {
      width = host.clientWidth || width;
      panelHeight = host.clientHeight || panelHeight;
      camera.aspect = width / Math.max(1, panelHeight);
      /* Fixed camera distance, variable field of view: the globe keeps the same
         share of the shorter panel edge in a 500px card and full-bleed, while
         wheel zoom still dollies for a real change in perspective. */
      camera.fov = THREE.MathUtils.radToDeg(
        2 * Math.atan(1 / (DEFAULT_DISTANCE * FRAME_FILL * Math.min(1, camera.aspect))),
      );
      camera.updateProjectionMatrix();
      renderer.setSize(width, panelHeight, false);
      const ratio = renderer.getPixelRatio();
      landMaterial.uniforms.uPixelRatio.value = ratio;
      markerMaterial.uniforms.uPixelRatio.value = ratio;
      haloMaterial.uniforms.uPixelRatio.value = ratio;
    };
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(host);

    let onScreen = true;
    const visibility = new IntersectionObserver(([entry]) => {
      onScreen = entry.isIntersecting;
    }, { threshold: 0.02 });
    visibility.observe(host);

    const element = renderer.domElement;
    element.tabIndex = 0;
    element.setAttribute("role", "application");
    element.setAttribute(
      "aria-label",
      `Globe of ${build.length} recorded indicator locations. Drag to rotate, scroll or use plus and minus to zoom, arrow keys to turn the view, escape to clear the focused country.`,
    );

    const view = viewRef.current;
    const pointer = { down: false, x: 0, y: 0, velYaw: 0, velPitch: 0, inside: false, clientX: 0, clientY: 0 };
    let ease: { yaw: number; pitch: number; until: number } | null = null;
    /* Undefined on purpose: the first frame then honours a selection that was
       already active when the globe mounted. */
    let lastSelected: string | null | undefined;

    const onPointerDown = (event: PointerEvent) => {
      if (event.button !== 0) return;
      pointer.down = true;
      pointer.x = event.clientX;
      pointer.y = event.clientY;
      pointer.velYaw = 0;
      pointer.velPitch = 0;
      ease = null;
      view.touched = performance.now();
      element.setPointerCapture(event.pointerId);
      element.style.cursor = "grabbing";
    };
    const onPointerMove = (event: PointerEvent) => {
      pointer.inside = true;
      pointer.clientX = event.clientX;
      pointer.clientY = event.clientY;
      /* Hovering holds the spin still: a marker a user is aiming at must not
         drift out from under the cursor before the click lands. */
      view.touched = performance.now();
      if (!pointer.down) return;
      const dx = event.clientX - pointer.x;
      const dy = event.clientY - pointer.y;
      pointer.x = event.clientX;
      pointer.y = event.clientY;
      view.yaw += dx * 0.0058;
      view.pitch = Math.max(-MAX_PITCH, Math.min(MAX_PITCH, view.pitch + dy * 0.0046));
      pointer.velYaw = dx * 0.0058;
      pointer.velPitch = dy * 0.0046;
      view.touched = performance.now();
    };
    const endPointer = (event: PointerEvent) => {
      pointer.down = false;
      view.touched = performance.now();
      element.style.cursor = hoverRef.current ? "pointer" : "grab";
      if (element.hasPointerCapture(event.pointerId)) element.releasePointerCapture(event.pointerId);
    };
    const onPointerLeave = () => {
      pointer.inside = false;
      if (hoverRef.current !== null) {
        hoverRef.current = null;
        setHovered(null);
      }
    };
    const zoomBy = (factor: number) => {
      view.distance = Math.max(MIN_DISTANCE, Math.min(MAX_DISTANCE, view.distance / factor));
      view.touched = performance.now();
      setZoomLabel(Number((DEFAULT_DISTANCE / view.distance).toFixed(1)));
    };
    const resetView = () => {
      const home = homeView(liveRef.current.points);
      view.distance = DEFAULT_DISTANCE;
      view.yaw = home.yaw;
      view.pitch = home.pitch;
      view.touched = performance.now();
      setZoomLabel(1);
    };
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      zoomBy(1 / Math.exp(event.deltaY * 0.0011));
    };
    const onKeyDown = (event: KeyboardEvent) => {
      const step = 0.12;
      if (event.key === "ArrowLeft") view.yaw -= step;
      else if (event.key === "ArrowRight") view.yaw += step;
      else if (event.key === "ArrowUp") view.pitch = Math.max(-MAX_PITCH, view.pitch - step);
      else if (event.key === "ArrowDown") view.pitch = Math.min(MAX_PITCH, view.pitch + step);
      else if (event.key === "+" || event.key === "=") zoomBy(1.24);
      else if (event.key === "-" || event.key === "_") zoomBy(1 / 1.24);
      else if (event.key === "Escape") liveRef.current.onSelect?.("");
      else return;
      event.preventDefault();
      event.stopPropagation();
      view.touched = performance.now();
      ease = null;
    };
    const onClick = (event: MouseEvent) => {
      const code = hoverRef.current;
      if (!code) return;
      if (Math.abs(event.clientX - pointer.x) > 4 || Math.abs(event.clientY - pointer.y) > 4) return;
      liveRef.current.onSelect?.(code);
    };
    element.addEventListener("pointerdown", onPointerDown);
    element.addEventListener("pointermove", onPointerMove);
    element.addEventListener("pointerup", endPointer);
    element.addEventListener("pointercancel", endPointer);
    element.addEventListener("pointerleave", onPointerLeave);
    element.addEventListener("wheel", onWheel, { passive: false });
    element.addEventListener("dblclick", resetView);
    element.addEventListener("keydown", onKeyDown);
    element.addEventListener("click", onClick);
    apiRef.current = { zoomBy, reset: resetView };

    const worldPoint = new THREE.Vector3();
    const cameraBearing = new THREE.Vector3();
    let frame = 0;
    let last = performance.now();
    let elapsed = 0;

    const renderFrame = (now: number) => {
      frame = requestAnimationFrame(renderFrame);
      if (!onScreen) return;
      const dt = Math.min(0.05, Math.max(0.001, (now - last) / 1000));
      last = now;
      const state = liveRef.current;
      const motion = reducedMotion ? 0 : 1;
      elapsed += dt * motion;

      if (state.selected !== lastSelected) {
        lastSelected = state.selected;
        const index = state.points.findIndex((point) => (point.code || "") === state.selected);
        if (index >= 0) {
          const v = markerLocal[index];
          const horizontal = Math.hypot(v.x, v.z);
          const target = Math.atan2(-v.x, v.z);
          const wrapped = ((target - view.yaw + Math.PI) % (Math.PI * 2) + Math.PI * 2) % (Math.PI * 2) - Math.PI;
          ease = {
            yaw: view.yaw + wrapped,
            pitch: Math.max(-0.72, Math.min(0.72, Math.atan2(v.y, horizontal) * 0.7)),
            until: now + 1600,
          };
          view.touched = now + 1600;
        } else {
          ease = null;
        }
      }

      if (!pointer.down) {
        if (Math.abs(pointer.velYaw) > 0.0003 || Math.abs(pointer.velPitch) > 0.0003) {
          view.yaw += pointer.velYaw * 2.4;
          view.pitch = Math.max(-MAX_PITCH, Math.min(MAX_PITCH, view.pitch + pointer.velPitch * 2.4));
          pointer.velYaw *= 0.9;
          pointer.velPitch *= 0.9;
        } else if (!ease && !pointer.inside && now - view.touched > IDLE_BEFORE_SPIN) {
          view.yaw += SPIN_RAD_PER_SEC * dt * motion;
        }
      }
      if (ease) {
        const k = 1 - Math.pow(0.004, dt);
        view.yaw += (ease.yaw - view.yaw) * k;
        view.pitch += (ease.pitch - view.pitch) * k;
        if (now > ease.until) ease = null;
      }
      globe.rotation.set(view.pitch, view.yaw, 0);
      camera.position.z = view.distance;
      const pxPerWorld = panelHeight / (2 * Math.tan((camera.fov * Math.PI) / 360) * view.distance);

      const density = state.mode === "density";
      landMaterial.uniforms.uTime.value = elapsed;
      markerMaterial.uniforms.uTime.value = elapsed;
      haloMaterial.uniforms.uTime.value = elapsed;
      haloMaterial.uniforms.uOpacity.value = density ? 0.7 : 0.2;
      markers.visible = !density;
      graticuleMaterial.opacity = density ? (dark ? 0.07 : 0.08) : dark ? 0.1 : 0.12;
      arcMaterial.opacity = dark ? 0.24 : 0.2;

      for (const ring of pulsing) {
        if (!state.pulse || reducedMotion) {
          ring.sprite.visible = false;
          continue;
        }
        const t = (elapsed * 0.45 + ring.phase) % 1;
        ring.sprite.visible = true;
        ring.sprite.scale.setScalar((ring.basePx / view.distance / pxPerWorld) * (1.5 + t * 2.6));
        ring.sprite.material.opacity = 0.42 * (1 - t) * (1 - t);
      }

      globe.updateMatrixWorld();
      cameraBearing.copy(camera.position).normalize();
      const rect = element.getBoundingClientRect();
      let nearest: { code: string; distance: number } | null = null;

      state.points.forEach((point, index) => {
        const local = markerLocal[index];
        const node = labelNodes.get(point.code || "");
        if (!local) {
          if (node) node.style.opacity = "0";
          return;
        }
        worldPoint.copy(local).applyMatrix4(globe.matrixWorld);
        const facing = worldPoint.clone().normalize().dot(cameraBearing) > 0.08;
        const screen = worldPoint.clone().project(camera);
        const x = (screen.x * 0.5 + 0.5) * width;
        const y = (-screen.y * 0.5 + 0.5) * panelHeight;
        const radiusPx = ((markerSizes[index] * POINT_SCALE) / Math.max(0.2, view.distance)) * 0.5;
        const visible = facing && screen.z < 1;

        if (node) {
          node.style.transform = `translate3d(${x.toFixed(1)}px, ${(y - radiusPx - 7).toFixed(1)}px, 0) translate(-50%, -100%)`;
          node.style.opacity = state.labels && visible && !density ? (state.selected === point.code ? "1" : "0.72") : "0";
          node.dataset.active = state.selected === point.code ? "1" : "0";
        }
        if (state.selected === point.code) {
          selectionRing.visible = visible;
          selectionRing.position.copy(local);
          selectionRing.scale.setScalar(((radiusPx * 3.4) / pxPerWorld) * 2);
        }
        if (pointer.inside && visible) {
          const distance = Math.hypot(pointer.clientX - rect.left - x, pointer.clientY - rect.top - y);
          if (distance < Math.max(14, radiusPx + 4) && (!nearest || distance < nearest.distance)) {
            nearest = { code: point.code || "", distance };
          }
        }
      });
      if (!state.selected) selectionRing.visible = false;

      const resolved = nearest ? nearest.code : null;
      if (resolved !== hoverRef.current) {
        hoverRef.current = resolved;
        setHovered(resolved);
        if (!pointer.down) element.style.cursor = resolved ? "pointer" : "grab";
      }
      const tip = tipRef.current;
      if (tip && hoverRef.current) {
        const index = state.points.findIndex((point) => (point.code || "") === hoverRef.current);
        if (index >= 0) {
          worldPoint.copy(markerLocal[index]).applyMatrix4(globe.matrixWorld);
          const screen = worldPoint.clone().project(camera);
          const x = (screen.x * 0.5 + 0.5) * width;
          const y = (-screen.y * 0.5 + 0.5) * panelHeight;
          const box = tip.getBoundingClientRect();
          tip.style.transform = `translate3d(${Math.max(8, Math.min(x + 18, width - box.width - 8)).toFixed(1)}px, ${Math.max(
            8,
            Math.min(y - box.height / 2, panelHeight - box.height - 8),
          ).toFixed(1)}px, 0)`;
        }
      }

      renderer.render(scene, camera);
    };
    frame = requestAnimationFrame(renderFrame);

    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      visibility.disconnect();
      element.removeEventListener("pointerdown", onPointerDown);
      element.removeEventListener("pointermove", onPointerMove);
      element.removeEventListener("pointerup", endPointer);
      element.removeEventListener("pointercancel", endPointer);
      element.removeEventListener("pointerleave", onPointerLeave);
      element.removeEventListener("wheel", onWheel);
      element.removeEventListener("dblclick", resetView);
      element.removeEventListener("keydown", onKeyDown);
      element.removeEventListener("click", onClick);
      apiRef.current = null;
      scene.traverse((object) => {
        // Sprite geometry is shared inside three, so only owned geometry is disposed.
        if (!(object as THREE.Sprite).isSprite) (object as THREE.Mesh).geometry?.dispose?.();
        const material = (object as THREE.Mesh).material as THREE.Material | THREE.Material[] | undefined;
        const list = Array.isArray(material) ? material : material ? [material] : [];
        for (const entry of list) {
          const withMap = entry as THREE.SpriteMaterial;
          if (withMap.map && withMap.map !== glowMap && withMap.map !== pulseMap && withMap.map !== selectionMap) {
            withMap.map.dispose();
          }
          entry.dispose();
        }
      });
      glowMap.dispose();
      pulseMap.dispose();
      selectionMap.dispose();
      renderer.dispose();
      if (element.parentElement === canvasHost) canvasHost.removeChild(element);
    };
  }, [themeMode, signature, webglOff, reducedMotion]);

  const hoveredPoint = hovered ? points.find((point) => (point.code || "") === hovered) || null : null;

  if (webglOff) {
    return (
      <SignalMap
        points={points}
        height={height}
        className={className}
        selected={selected}
        onSelect={onSelect}
        labels={labels}
        mode={mode}
        markerScale={1.3}
        pulse={pulse}
        interactive
      />
    );
  }

  return (
    <div ref={hostRef} className={clsx("globe-shell relative w-full overflow-hidden", className)} style={{ height }}>
      <div ref={canvasHostRef} className="absolute inset-0" />
      <div className="pointer-events-none absolute inset-0 overflow-hidden">
        {points.map((point) => (
          <span key={`${point.code}-${point.country}`} className="globe-label" data-code={point.code || ""}>
            {point.code || point.country?.slice(0, 2).toUpperCase()}
            <em>{fmtNumber(point.count)}</em>
          </span>
        ))}
      </div>

      <div className="globe-caption pointer-events-none absolute left-1/2 top-2.5 hidden -translate-x-1/2 whitespace-nowrap sm:block">
        Drag to rotate · scroll to zoom · click a marker
      </div>

      <div className="absolute bottom-2.5 right-2.5 z-20 flex items-center gap-1 rounded-lg border border-line-strong bg-sunken/80 p-0.5 shadow-lift backdrop-blur-md">
        <button
          type="button"
          onClick={() => apiRef.current?.zoomBy(1 / 1.35)}
          aria-label="Zoom out"
          className="grid h-6 w-6 place-items-center rounded-md text-[13px] leading-none text-mist transition-colors hover:bg-ion/10 hover:text-ion"
        >
          −
        </button>
        <button
          type="button"
          onClick={() => apiRef.current?.reset()}
          aria-label="Reset globe view"
          className="tnum h-6 min-w-[40px] rounded-md px-1 font-mono text-[8.5px] uppercase tracking-[0.08em] text-dim transition-colors hover:bg-ion/10 hover:text-ion"
        >
          {zoomLabel.toFixed(1)}×
        </button>
        <button
          type="button"
          onClick={() => apiRef.current?.zoomBy(1.35)}
          aria-label="Zoom in"
          className="grid h-6 w-6 place-items-center rounded-md text-[13px] leading-none text-mist transition-colors hover:bg-ion/10 hover:text-ion"
        >
          +
        </button>
      </div>

      {hoveredPoint && (
        <div
          ref={tipRef}
          className="pointer-events-none absolute left-0 top-0 z-30 w-[190px] rounded-lg border border-line-strong bg-tooltip/95 px-2.5 py-2 shadow-lift backdrop-blur-md"
        >
          <div className="flex items-center justify-between gap-2">
            <span className="truncate text-[11px] font-medium text-ink">{hoveredPoint.country || "Unknown"}</span>
            <span className="shrink-0 font-mono text-[8px] uppercase tracking-[0.1em] text-ion">{hoveredPoint.code}</span>
          </div>
          <div className="tnum mt-1 flex flex-wrap items-center gap-x-1.5 font-mono text-[8.5px] uppercase tracking-[0.06em] text-dim">
            <span>{fmtNumber(hoveredPoint.count)} indicator{hoveredPoint.count === 1 ? "" : "s"}</span>
            {typeof hoveredPoint.records === "number" && (
              <span>· {fmtNumber(hoveredPoint.records)} record{hoveredPoint.records === 1 ? "" : "s"}</span>
            )}
            {typeof hoveredPoint.maxRisk === "number" && (
              <span>
                · peak <span style={{ color: riskColor(hoveredPoint.maxRisk) }}>{hoveredPoint.maxRisk.toFixed(0)}</span>
              </span>
            )}
          </div>
          {!!hoveredPoint.classes?.length && (
            <div className="mt-1.5 flex flex-wrap gap-1">
              {hoveredPoint.classes.slice(0, 3).map((name) => (
                <span key={name} className="chip py-[1px] text-[7.5px]">
                  {name}
                </span>
              ))}
            </div>
          )}
          <div className="mt-1.5 border-t border-line pt-1 font-mono text-[7px] uppercase tracking-[0.08em] text-dim">
            Location is source metadata · not attribution
          </div>
        </div>
      )}

      <p className="sr-only">
        Globe of {points.length} recorded indicator locations. The origin ranking beside it lists the same countries and
        counts; selecting either focuses that country.
      </p>
    </div>
  );
}
