import { useEffect, useRef, useState } from "react";
import * as THREE from "three";

function glowTexture(): THREE.Texture {
  const canvas = document.createElement("canvas");
  canvas.width = 256;
  canvas.height = 256;
  const ctx = canvas.getContext("2d")!;
  const gradient = ctx.createRadialGradient(128, 128, 0, 128, 128, 128);
  gradient.addColorStop(0, "rgba(73,184,255,0.5)");
  gradient.addColorStop(0.36, "rgba(40,160,255,0.3)");
  gradient.addColorStop(0.66, "rgba(45,143,232,0.1)");
  gradient.addColorStop(1, "rgba(0,0,0,0)");
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, 256, 256);
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

function dotTexture(): THREE.Texture {
  const canvas = document.createElement("canvas");
  canvas.width = 32;
  canvas.height = 32;
  const ctx = canvas.getContext("2d")!;
  const gradient = ctx.createRadialGradient(16, 16, 0, 16, 16, 16);
  gradient.addColorStop(0, "rgba(255,255,255,1)");
  gradient.addColorStop(0.4, "rgba(255,255,255,0.65)");
  gradient.addColorStop(1, "rgba(255,255,255,0)");
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, 32, 32);
  const texture = new THREE.CanvasTexture(canvas);
  texture.colorSpace = THREE.SRGBColorSpace;
  return texture;
}

function shieldShape(): THREE.Shape {
  const shape = new THREE.Shape();
  shape.moveTo(0, 1.14);
  shape.bezierCurveTo(-0.4, 1.19, -0.76, 1.1, -0.93, 0.96);
  shape.lineTo(-0.95, 0.22);
  shape.bezierCurveTo(-0.95, -0.34, -0.66, -0.78, 0, -1.19);
  shape.bezierCurveTo(0.66, -0.78, 0.95, -0.34, 0.95, 0.22);
  shape.lineTo(0.93, 0.96);
  shape.bezierCurveTo(0.76, 1.1, 0.4, 1.19, 0, 1.14);
  return shape;
}

export function Shield3D({ className }: { className?: string }) {
  const hostRef = useRef<HTMLDivElement>(null);
  const [unsupported, setUnsupported] = useState(false);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 100);
    camera.position.set(0, 0.16, 5.1);

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
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.12;
    host.appendChild(renderer.domElement);
    renderer.domElement.style.width = "100%";
    renderer.domElement.style.height = "100%";
    renderer.domElement.style.display = "block";

    const rig = new THREE.Group();
    rig.rotation.set(-0.06, -0.28, 0.02);
    scene.add(rig);

    const shape = shieldShape();
    const geometry = new THREE.ExtrudeGeometry(shape, {
      depth: 0.32,
      bevelEnabled: true,
      bevelThickness: 0.075,
      bevelSize: 0.065,
      bevelSegments: 5,
      curveSegments: 36,
    });
    geometry.center();

    const shell = new THREE.Mesh(
      geometry,
      new THREE.MeshPhysicalMaterial({
        color: 0x0b2a48,
        metalness: 0.62,
        roughness: 0.2,
        clearcoat: 1,
        clearcoatRoughness: 0.12,
        emissive: 0x0d3a63,
        emissiveIntensity: 0.5,
        reflectivity: 0.9,
      }),
    );
    rig.add(shell);

    const outlinePoints = shape.getPoints(96).map((point) => new THREE.Vector3(point.x * 0.74, point.y * 0.74, 0.262));
    const outline = new THREE.LineLoop(
      new THREE.BufferGeometry().setFromPoints(outlinePoints),
      new THREE.LineBasicMaterial({ color: 0x64d8ff, transparent: true, opacity: 0.34 }),
    );
    rig.add(outline);

    const core = new THREE.Mesh(
      new THREE.TorusGeometry(0.33, 0.008, 10, 160),
      new THREE.MeshBasicMaterial({ color: 0x64d8ff, transparent: true, opacity: 0.85 }),
    );
    core.position.set(0, 0.02, 0.27);
    rig.add(core);

    const coreDot = new THREE.Mesh(
      new THREE.SphereGeometry(0.075, 24, 24),
      new THREE.MeshBasicMaterial({ color: 0xbdeeff }),
    );
    coreDot.position.set(0, 0.02, 0.28);
    rig.add(coreDot);

    const orbitAccent = new THREE.Mesh(
      new THREE.TorusGeometry(1.46, 0.006, 8, 220),
      new THREE.MeshBasicMaterial({ color: 0x49b8ff, transparent: true, opacity: 0.34 }),
    );
    orbitAccent.rotation.set(1.14, 0.32, 0.2);
    rig.add(orbitAccent);

    const orbitViolet = new THREE.Mesh(
      new THREE.TorusGeometry(1.66, 0.004, 8, 220),
      new THREE.MeshBasicMaterial({ color: 0x9a8cff, transparent: true, opacity: 0.26 }),
    );
    orbitViolet.rotation.set(0.62, -0.42, 0.4);
    rig.add(orbitViolet);

    const satellites = [0x64d8ff, 0x49b8ff, 0x9a8cff].map((color, index) => {
      const satellite = new THREE.Mesh(
        new THREE.SphereGeometry(index === 2 ? 0.026 : 0.034, 12, 12),
        new THREE.MeshBasicMaterial({ color }),
      );
      rig.add(satellite);
      return { mesh: satellite, radius: index === 2 ? 1.66 : 1.46, speed: 0.22 + index * 0.07, phase: index * 2.1, tilt: index === 2 ? 0.62 : 1.14 };
    });

    const halo = new THREE.Sprite(
      new THREE.SpriteMaterial({ map: glowTexture(), transparent: true, opacity: 0.72, depthWrite: false, depthTest: false }),
    );
    halo.scale.setScalar(6.2);
    halo.position.set(0, -0.1, -1.6);
    halo.renderOrder = -1;
    scene.add(halo);

    const count = 260;
    const positions = new Float32Array(count * 3);
    const colors = new Float32Array(count * 3);
    const palette = [new THREE.Color(0x49b8ff), new THREE.Color(0x64d8ff), new THREE.Color(0xe4f4ff), new THREE.Color(0x9a8cff)];
    for (let i = 0; i < count; i++) {
      const radius = 1.9 + Math.random() * 2.2;
      const theta = Math.random() * Math.PI * 2;
      const phi = Math.acos(2 * Math.random() - 1);
      positions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
      positions[i * 3 + 1] = radius * Math.cos(phi) * 0.72;
      positions[i * 3 + 2] = radius * Math.sin(phi) * Math.sin(theta);
      const color = palette[Math.random() < 0.64 ? Math.floor(Math.random() * 2) : 2 + Math.floor(Math.random() * 2)];
      colors[i * 3] = color.r;
      colors[i * 3 + 1] = color.g;
      colors[i * 3 + 2] = color.b;
    }
    const dustGeometry = new THREE.BufferGeometry();
    dustGeometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
    dustGeometry.setAttribute("color", new THREE.BufferAttribute(colors, 3));
    const dust = new THREE.Points(
      dustGeometry,
      new THREE.PointsMaterial({
        size: 0.034,
        map: dotTexture(),
        vertexColors: true,
        transparent: true,
        opacity: 0.62,
        depthWrite: false,
        blending: THREE.AdditiveBlending,
        sizeAttenuation: true,
      }),
    );
    rig.add(dust);

    scene.add(new THREE.AmbientLight(0x7fb4d4, 0.85));
    const keyLight = new THREE.DirectionalLight(0xe6f3ff, 2.6);
    keyLight.position.set(2.6, 3.2, 4.2);
    scene.add(keyLight);
    const rimLight = new THREE.DirectionalLight(0x49b8ff, 1.8);
    rimLight.position.set(-3.2, -1.4, 2.2);
    scene.add(rimLight);
    const accentLight = new THREE.PointLight(0x9a8cff, 14, 9, 2);
    accentLight.position.set(-1.2, -2.2, 1.4);
    scene.add(accentLight);
    const glowLight = new THREE.PointLight(0x64d8ff, 20, 12, 2);
    glowLight.position.set(2.2, 1.8, -1.6);
    scene.add(glowLight);

    let width = host.clientWidth || 520;
    let height = host.clientHeight || 520;
    const resize = () => {
      width = host.clientWidth || width;
      height = host.clientHeight || height;
      camera.aspect = width / Math.max(1, height);
      camera.updateProjectionMatrix();
      renderer.setSize(width, height, false);
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

    let targetX = 0;
    let targetY = 0;
    const onPointer = (event: PointerEvent) => {
      targetY = (event.clientX / window.innerWidth - 0.5) * 0.5;
      targetX = (event.clientY / window.innerHeight - 0.5) * 0.34;
    };
    window.addEventListener("pointermove", onPointer, { passive: true });

    const clock = new THREE.Clock();
    let frame = 0;
    let last = 0;
    const animate = (time: number) => {
      frame = requestAnimationFrame(animate);
      if (!visible) return;
      if (time - last < 32) return;
      last = time;
      const motion = reduced ? 0 : 1;
      const elapsed = clock.getElapsedTime();
      const sway = Math.sin(elapsed * 0.34) * 0.12 * motion;
      rig.rotation.y = -0.26 + sway + targetY * 0.6;
      rig.rotation.x += (-0.05 + Math.sin(elapsed * 0.24) * 0.045 + targetX * 0.4 - rig.rotation.x) * 0.04;
      rig.position.y = Math.sin(elapsed * 0.5) * 0.035 * motion;
      orbitAccent.rotation.y += 0.0022 * motion;
      orbitViolet.rotation.y -= 0.0016 * motion;
      core.rotation.z += 0.0018 * motion;
      coreDot.scale.setScalar(1 + Math.sin(elapsed * 1.6) * 0.1 * motion);
      dust.rotation.y += 0.0008 * motion;
      satellites.forEach((satellite) => {
        const angle = elapsed * satellite.speed * motion + satellite.phase;
        const cosTilt = Math.cos(satellite.tilt);
        satellite.mesh.position.set(
          Math.cos(angle) * satellite.radius,
          Math.sin(angle) * satellite.radius * cosTilt,
          Math.sin(angle) * satellite.radius * Math.sin(satellite.tilt) * 0.55,
        );
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
  }, []);

  return (
    <div ref={hostRef} className={className} aria-hidden="true">
      {unsupported && (
        <div className="grid h-full w-full place-items-center">
          <svg viewBox="0 0 200 240" className="h-[72%] w-auto" aria-hidden="true">
            <defs>
              <linearGradient id="shield-fallback" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stopColor="#2d8fe8" />
                <stop offset="55%" stopColor="#13385c" />
                <stop offset="100%" stopColor="#061222" />
              </linearGradient>
              <linearGradient id="shield-edge" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stopColor="#e4f4ff" />
                <stop offset="60%" stopColor="#64d8ff" />
                <stop offset="100%" stopColor="#49b8ff" />
              </linearGradient>
            </defs>
            <path d="M100 10 178 46v74c0 46-30 82-78 108-48-26-78-62-78-108V46L100 10Z" fill="url(#shield-fallback)" stroke="url(#shield-edge)" strokeWidth="2" />
            <path d="M100 44 150 67v50c0 30-20 54-50 70-30-16-50-40-50-70V67l50-23Z" fill="none" stroke="rgba(100,216,255,0.35)" strokeWidth="1.2" />
            <circle cx="100" cy="112" r="16" fill="none" stroke="#64d8ff" strokeWidth="1.6" />
            <circle cx="100" cy="112" r="4" fill="#d6ecff" />
          </svg>
        </div>
      )}
    </div>
  );
}
