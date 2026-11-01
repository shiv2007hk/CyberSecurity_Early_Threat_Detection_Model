import { useEffect, useRef, useState } from "react";
import * as THREE from "three";

type Hotspot = { lat: number; lon: number; label: string; tone: string };

const HOTSPOTS: Hotspot[] = [
  { lat: 52.37, lon: 4.9, label: "EU-WEST", tone: "#64d8ff" },
  { lat: 1.35, lon: 103.82, label: "AP-SOUTH", tone: "#49b8ff" },
  { lat: 39.9, lon: 116.4, label: "AP-EAST", tone: "#9a8cff" },
  { lat: 38.9, lon: -77.5, label: "NA-EAST", tone: "#64d8ff" },
  { lat: 19.07, lon: 72.88, label: "IN-WEST", tone: "#ffd166" },
  { lat: -23.55, lon: -46.63, label: "SA-EAST", tone: "#49b8ff" },
  { lat: 51.5, lon: -0.12, label: "EU-NORTH", tone: "#ff963d" },
  { lat: 35.68, lon: 139.69, label: "AP-NORTH", tone: "#64d8ff" },
];

function latLonToVector(lat: number, lon: number, radius = 1): THREE.Vector3 {
  const phi = (90 - lat) * (Math.PI / 180);
  const theta = (lon + 180) * (Math.PI / 180);
  return new THREE.Vector3(
    -radius * Math.sin(phi) * Math.cos(theta),
    radius * Math.cos(phi),
    radius * Math.sin(phi) * Math.sin(theta),
  );
}

function dotTexture(color: string): THREE.Texture {
  const canvas = document.createElement("canvas");
  canvas.width = 64;
  canvas.height = 64;
  const ctx = canvas.getContext("2d")!;
  const gradient = ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
  gradient.addColorStop(0, color);
  gradient.addColorStop(0.28, color);
  gradient.addColorStop(1, "rgba(0,0,0,0)");
  ctx.fillStyle = gradient;
  ctx.beginPath();
  ctx.arc(32, 32, 32, 0, Math.PI * 2);
  ctx.fill();
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

function haloTexture(): THREE.Texture {
  const canvas = document.createElement("canvas");
  canvas.width = 256;
  canvas.height = 256;
  const ctx = canvas.getContext("2d")!;
  const gradient = ctx.createRadialGradient(128, 128, 0, 128, 128, 128);
  gradient.addColorStop(0, "rgba(45,143,232,0.5)");
  gradient.addColorStop(0.34, "rgba(40,160,255,0.32)");
  gradient.addColorStop(0.62, "rgba(45,143,232,0.12)");
  gradient.addColorStop(1, "rgba(0,0,0,0)");
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, 256, 256);
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

const PARTICLE_PALETTE = [
  { color: new THREE.Color(0x49b8ff), weight: 0.42 },
  { color: new THREE.Color(0x64d8ff), weight: 0.3 },
  { color: new THREE.Color(0x2d8fe8), weight: 0.14 },
  { color: new THREE.Color(0x8be4ff), weight: 0.09 },
  { color: new THREE.Color(0x9a8cff), weight: 0.035 },
  { color: new THREE.Color(0xe4f4ff), weight: 0.015 },
];

function pickParticleColor(): THREE.Color {
  const roll = Math.random();
  let acc = 0;
  for (const entry of PARTICLE_PALETTE) {
    acc += entry.weight;
    if (roll <= acc) return entry.color;
  }
  return PARTICLE_PALETTE[0].color;
}

export function Globe({
  className,
  paused = false,
  density = 1,
}: {
  className?: string;
  paused?: boolean;
  density?: number;
}) {
  const hostRef = useRef<HTMLDivElement>(null);
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  const [unsupported, setUnsupported] = useState(false);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(42, 1, 0.1, 100);
    camera.position.set(0, 0.1, 3.2);

    let renderer: THREE.WebGLRenderer;
    try {
      renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: "high-performance" });
    } catch {
      setUnsupported(true);
      return;
    }
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.75));
    renderer.setClearColor(0x000000, 0);
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    host.appendChild(renderer.domElement);
    renderer.domElement.style.width = "100%";
    renderer.domElement.style.height = "100%";
    renderer.domElement.style.display = "block";

    const globe = new THREE.Group();
    globe.rotation.set(-0.32, 2.3, -0.12);
    scene.add(globe);

    const shell = new THREE.Mesh(
      new THREE.SphereGeometry(0.962, 64, 48),
      new THREE.MeshStandardMaterial({
        color: 0x061222,
        roughness: 0.72,
        metalness: 0.32,
        emissive: 0x102a45,
        emissiveIntensity: 0.55,
      }),
    );
    globe.add(shell);

    const ambient = new THREE.AmbientLight(0x4f8fbd, 1.2);
    const key = new THREE.DirectionalLight(0x64d8ff, 1.35);
    key.position.set(3, 2, 4);
    const rim = new THREE.DirectionalLight(0x49b8ff, 0.9);
    rim.position.set(-4, -1, -2.5);
    scene.add(ambient, key, rim);

    const glow = new THREE.Sprite(
      new THREE.SpriteMaterial({
        map: haloTexture(),
        transparent: true,
        opacity: 0.62,
        depthWrite: false,
        depthTest: false,
        blending: THREE.AdditiveBlending,
      }),
    );
    glow.scale.setScalar(3.6);
    glow.renderOrder = -1;
    scene.add(glow);

    const wire = new THREE.LineSegments(
      new THREE.WireframeGeometry(new THREE.SphereGeometry(0.966, 26, 18)),
      new THREE.LineBasicMaterial({ color: 0x2d8fe8, transparent: true, opacity: 0.12 }),
    );
    globe.add(wire);

    const gridMaterial = new THREE.LineBasicMaterial({ color: 0x3a93d8, transparent: true, opacity: 0.08 });
    for (let lat = -60; lat <= 60; lat += 30) {
      const phi = (90 - lat) * (Math.PI / 180);
      const y = Math.cos(phi);
      const radius = Math.sin(phi) * 0.97;
      const points: THREE.Vector3[] = [];
      for (let i = 0; i <= 96; i++) {
        const angle = (i / 96) * Math.PI * 2;
        points.push(new THREE.Vector3(Math.cos(angle) * radius, y, Math.sin(angle) * radius));
      }
      globe.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(points), gridMaterial));
    }
    for (let lon = 0; lon < 180; lon += 60) {
      const points: THREE.Vector3[] = [];
      for (let i = 0; i <= 96; i++) {
        const angle = (i / 96) * Math.PI * 2;
        const lat = angle - Math.PI / 2;
        points.push(latLonToVector((lat * 180) / Math.PI, lon, 0.97));
      }
      globe.add(new THREE.Line(new THREE.BufferGeometry().setFromPoints(points), gridMaterial));
    }

    const count = Math.floor(1500 * density);
    const positions = new Float32Array(count * 3);
    const colors = new Float32Array(count * 3);
    const sizes = new Float32Array(count);
    const phases = new Float32Array(count);
    const golden = Math.PI * (3 - Math.sqrt(5));
    for (let i = 0; i < count; i++) {
      const y = 1 - (i / Math.max(1, count - 1)) * 2;
      const ring = Math.sqrt(Math.max(0, 1 - y * y));
      const theta = golden * i;
      const dir = new THREE.Vector3(Math.cos(theta) * ring, y, Math.sin(theta) * ring);
      const wave =
        Math.sin(dir.x * 3.6 + 0.7) * Math.cos(dir.y * 3.1 - 1.2) * 0.048 +
        Math.sin(dir.z * 5.4 + 2.1) * 0.024 +
        Math.sin((dir.x + dir.y) * 7.1) * 0.012;
      const haloLayer = Math.random() < 0.17;
      const radius = (haloLayer ? 1.035 + Math.random() * 0.11 : 0.995 + Math.random() * 0.02) + wave;
      const v = dir.multiplyScalar(radius);
      positions.set([v.x, v.y, v.z], i * 3);
      const color = pickParticleColor().clone().multiplyScalar(0.5 + Math.random() * 0.65);
      colors.set([color.r, color.g, color.b], i * 3);
      sizes[i] = Math.random() < 0.07 ? 0.018 + Math.random() * 0.016 : 0.004 + Math.random() * 0.007;
      phases[i] = Math.random() * Math.PI * 2;
    }
    const pointsGeometry = new THREE.BufferGeometry();
    pointsGeometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    pointsGeometry.setAttribute("aColor", new THREE.BufferAttribute(colors, 3));
    pointsGeometry.setAttribute("aSize", new THREE.BufferAttribute(sizes, 1));
    pointsGeometry.setAttribute("aPhase", new THREE.BufferAttribute(phases, 1));
    const pointsMaterial = new THREE.ShaderMaterial({
      transparent: true,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
      uniforms: {
        uPixelRatio: { value: renderer.getPixelRatio() },
        uTime: { value: 0 },
      },
      vertexShader: `
        attribute vec3 aColor;
        attribute float aSize;
        attribute float aPhase;
        uniform float uPixelRatio;
        uniform float uTime;
        varying vec3 vColor;
        varying float vTwinkle;
        void main() {
          vColor = aColor;
          vTwinkle = 0.72 + 0.28 * sin(uTime * 1.15 + aPhase);
          vec4 mv = modelViewMatrix * vec4(position, 1.0);
          gl_PointSize = aSize * uPixelRatio * (900.0 / -mv.z) * vTwinkle;
          gl_Position = projectionMatrix * mv;
        }
      `,
      fragmentShader: `
        varying vec3 vColor;
        varying float vTwinkle;
        void main() {
          float d = length(gl_PointCoord - vec2(0.5));
          if (d > 0.5) discard;
          float alpha = 1.0 - smoothstep(0.0, 0.5, d);
          gl_FragColor = vec4(vColor, alpha * vTwinkle);
        }
      `,
    });
    const points = new THREE.Points(pointsGeometry, pointsMaterial);
    globe.add(points);

    const atmosphere = new THREE.Mesh(
      new THREE.SphereGeometry(1.11, 64, 48),
      new THREE.ShaderMaterial({
        transparent: true,
        blending: THREE.AdditiveBlending,
        side: THREE.BackSide,
        depthWrite: false,
        uniforms: {
          glowColor: { value: new THREE.Color(0x2d8fe8) },
          accent: { value: new THREE.Color(0x64d8ff) },
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
          uniform vec3 glowColor;
          uniform vec3 accent;
          varying vec3 vNormal;
          varying vec3 vView;
          void main() {
              float rim = pow(1.0 - abs(dot(vNormal, vView)), 3.2);
            vec3 color = mix(glowColor, accent, rim * 0.55);
            gl_FragColor = vec4(color, rim * 0.48);
          }
        `,
      }),
    );
    scene.add(atmosphere);

    const arcs = new THREE.Group();
    globe.add(arcs);
    const arcPalette = [0x64d8ff, 0x49b8ff, 0x9a8cff, 0x8be4ff];
    const arcCount = Math.floor(12 * density);
    const arcComets: Array<{ mesh: THREE.Mesh; curve: THREE.QuadraticBezierCurve3; speed: number; offset: number }> = [];

    for (let i = 0; i < arcCount; i++) {
      const a = HOTSPOTS[i % HOTSPOTS.length];
      const b = HOTSPOTS[(i * 3 + 2) % HOTSPOTS.length];
      if (a === b) continue;
      const start = latLonToVector(a.lat, a.lon, 0.99);
      const end = latLonToVector(b.lat, b.lon, 0.99);
      const mid = start.clone().add(end).multiplyScalar(0.5).normalize().multiplyScalar(1 + start.distanceTo(end) * 0.2);
      const curve = new THREE.QuadraticBezierCurve3(start, mid, end);
      const geometry = new THREE.BufferGeometry().setFromPoints(curve.getPoints(60));
      const color = arcPalette[i % arcPalette.length];
      arcs.add(
        new THREE.Line(
          geometry,
          new THREE.LineBasicMaterial({ color, transparent: true, opacity: 0.18 + (i % 3) * 0.1, blending: THREE.AdditiveBlending, depthWrite: false }),
        ),
      );
      if (i % 2 === 0) {
        const comet = new THREE.Mesh(
          new THREE.SphereGeometry(0.013, 8, 8),
          new THREE.MeshBasicMaterial({ color, transparent: true, opacity: 0.95, blending: THREE.AdditiveBlending }),
        );
        arcs.add(comet);
        arcComets.push({ mesh: comet, curve, speed: 0.06 + Math.random() * 0.08, offset: Math.random() });
      }
    }

    const markers: Array<{ sprite: THREE.Sprite; base: number; phase: number }> = [];
    HOTSPOTS.forEach((spot, index) => {
      const texture = dotTexture(spot.tone);
      const material = new THREE.SpriteMaterial({ map: texture, transparent: true, depthWrite: false, blending: THREE.AdditiveBlending });
      const sprite = new THREE.Sprite(material);
      sprite.position.copy(latLonToVector(spot.lat, spot.lon, 1.01));
      const base = 0.055;
      sprite.scale.setScalar(base);
      globe.add(sprite);
      markers.push({ sprite, base, phase: index * 0.7 });

      const ring = new THREE.Sprite(new THREE.SpriteMaterial({ map: texture, transparent: true, opacity: 0.2, depthWrite: false, blending: THREE.AdditiveBlending }));
      ring.position.copy(sprite.position);
      ring.scale.setScalar(0.125);
      globe.add(ring);
      markers.push({ sprite: ring, base: 0.125, phase: index * 0.7 + 1.2 });
    });

    const orbitMaterial = new THREE.LineBasicMaterial({ color: 0x6f9fc8, transparent: true, opacity: 0.18 });
    const orbit1 = new THREE.Line(new THREE.BufferGeometry().setFromPoints(new THREE.EllipseCurve(0, 0, 1.34, 1.34, 0, Math.PI * 2).getPoints(160).map((p) => new THREE.Vector3(p.x, 0, p.y))), orbitMaterial);
    orbit1.rotation.z = 0.32;
    scene.add(orbit1);

    const dashedRing = new THREE.Line(
      new THREE.BufferGeometry().setFromPoints(new THREE.EllipseCurve(0, 0, 1.5, 1.5, 0, Math.PI * 2).getPoints(220).map((p) => new THREE.Vector3(p.x, 0, p.y))),
      new THREE.LineDashedMaterial({ color: 0x64d8ff, transparent: true, opacity: 0.2, dashSize: 0.05, gapSize: 0.09 }),
    );
    dashedRing.computeLineDistances();
    dashedRing.rotation.set(0.85, 0.15, 0.3);
    scene.add(dashedRing);

    const halo = new THREE.Mesh(
      new THREE.RingGeometry(1.32, 1.325, 180),
      new THREE.MeshBasicMaterial({ color: 0x49b8ff, transparent: true, opacity: 0.14, side: THREE.DoubleSide }),
    );
    halo.rotation.x = Math.PI / 2.05;
    scene.add(halo);

    let width = host.clientWidth || 520;
    let height = host.clientHeight || 520;
    const resize = () => {
      width = host.clientWidth || width;
      height = host.clientHeight || height;
      camera.aspect = width / Math.max(1, height);
      camera.updateProjectionMatrix();
      renderer.setSize(width, height, false);
      pointsMaterial.uniforms.uPixelRatio.value = renderer.getPixelRatio();
    };
    resize();
    const observer = new ResizeObserver(resize);
    observer.observe(host);

    let visible = true;
    const visibility = new IntersectionObserver(
      ([entry]) => {
        visible = entry.isIntersecting;
      },
      { threshold: 0.02 },
    );
    visibility.observe(host);

    let hoverX = 0;
    let hoverY = 0;
    const onPointer = (event: PointerEvent) => {
      hoverX = (event.clientX / window.innerWidth - 0.5) * 0.18;
      hoverY = (event.clientY / window.innerHeight - 0.5) * 0.12;
    };
    window.addEventListener("pointermove", onPointer, { passive: true });

    const clock = new THREE.Clock();
    let frame = 0;
    let last = 0;
    let elapsedTime = 0;
    const animate = (time: number) => {
      frame = requestAnimationFrame(animate);
      if (!visible) return;
      if (time - last < 32) return;
      last = time;
      const motion = reduced || pausedRef.current ? 0 : 1;
      const elapsed = clock.getElapsedTime();
      elapsedTime += 0.032 * motion;
      pointsMaterial.uniforms.uTime.value = elapsedTime;
      globe.rotation.y += 0.0011 * motion;
      globe.rotation.x += (hoverY * 0.35 - (globe.rotation.x + 0.32)) * 0.012 * motion;
      globe.rotation.z += (hoverX * 0.2 - (globe.rotation.z + 0.12)) * 0.012 * motion;
      points.rotation.y += 0.00022 * motion;
      orbit1.rotation.y += 0.0008 * motion;
      dashedRing.rotation.z += 0.0011 * motion;
      halo.rotation.z -= 0.0006 * motion;
      glow.material.opacity = 0.56 + Math.sin(elapsed * 0.5) * 0.06 * motion;
      arcComets.forEach((comet) => {
        const t = (elapsed * comet.speed * motion + comet.offset) % 1;
        comet.mesh.position.copy(comet.curve.getPoint(t));
        (comet.mesh.material as THREE.MeshBasicMaterial).opacity = 0.25 + Math.sin(t * Math.PI) * 0.7;
      });
      markers.forEach((marker) => {
        const pulse = 1 + Math.sin(elapsed * 1.6 + marker.phase) * 0.16 * motion;
        marker.sprite.scale.setScalar(marker.base * pulse);
      });
      renderer.render(scene, camera);
    };
    frame = requestAnimationFrame(animate);

    return () => {
      cancelAnimationFrame(frame);
      observer.disconnect();
      visibility.disconnect();
      window.removeEventListener("pointermove", onPointer);
      scene.traverse((object) => {
        const mesh = object as THREE.Mesh;
        if (mesh.geometry) mesh.geometry.dispose();
        const material = mesh.material as THREE.Material | THREE.Material[] | undefined;
        if (Array.isArray(material)) material.forEach((m) => m.dispose());
        else material?.dispose();
      });
      renderer.dispose();
      if (renderer.domElement.parentElement === host) host.removeChild(renderer.domElement);
    };
  }, [density]);

  return (
    <div ref={hostRef} className={className} aria-hidden="true">
      {unsupported && (
        <div
          className="h-full w-full rounded-full"
          style={{
            background:
              "radial-gradient(circle at 38% 32%, rgba(100,216,255,0.35), transparent 42%), radial-gradient(circle at 62% 64%, rgba(73,184,255,0.28), transparent 52%), radial-gradient(circle at 50% 50%, #102a45 0%, #061222 62%, transparent 72%)",
          }}
        />
      )}
    </div>
  );
}

export function RadarSweep({ className }: { className?: string }) {
  return (
    <div className={className} aria-hidden="true">
      <div className="relative h-full w-full">
        <div className="absolute inset-[6%] rounded-full border border-ion/15" />
        <div className="absolute inset-[20%] rounded-full border border-ion/10" />
        <div className="absolute inset-[34%] rounded-full border border-ion/[0.08]" />
        <div className="absolute left-1/2 top-1/2 h-px w-full -translate-x-1/2 -translate-y-1/2 bg-ion/[0.08]" />
        <div className="absolute left-1/2 top-1/2 h-full w-px -translate-x-1/2 -translate-y-1/2 bg-ion/[0.08]" />
        <div
          className="absolute inset-[6%] rounded-full opacity-60"
          style={{
            background: "conic-gradient(from 0deg, rgba(100,216,255,0.24), rgba(100,216,255,0.045) 42deg, transparent 78deg, transparent 360deg)",
            animation: "spin 9s linear infinite",
          }}
        />
        <div className="absolute inset-[6%] rounded-full" style={{ background: "radial-gradient(circle, transparent 58%, rgba(100,216,255,0.05) 100%)" }} />
        <span className="absolute left-[63%] top-[31%] h-1 w-1 rounded-full bg-ion shadow-[0_0_10px_2px_rgba(100,216,255,0.5)]" />
        <span className="absolute left-[38%] top-[62%] h-1 w-1 rounded-full bg-pulse shadow-[0_0_10px_2px_rgba(73,184,255,0.45)]" />
        <span className="absolute left-[71%] top-[68%] h-0.5 w-0.5 rounded-full bg-violet" />
      </div>
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
