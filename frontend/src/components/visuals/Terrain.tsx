import clsx from "clsx";

const FAR =
  "M0 620 60 585 110 600 170 520 225 555 280 470 340 520 395 440 455 500 520 410 575 462 640 380 700 445 760 392 820 462 880 405 940 470 1000 420 1065 500 1120 452 1190 530 1250 470 1310 545 1375 488 1440 560 1500 512 1560 575 1600 545 1600 900 0 900Z";
const MID =
  "M0 720 55 665 105 700 160 610 215 672 270 578 330 648 380 585 445 660 500 590 560 662 615 600 680 675 740 612 800 690 860 620 920 700 980 632 1040 705 1100 645 1165 718 1230 650 1290 730 1350 668 1410 742 1475 682 1540 748 1600 700 1600 900 0 900Z";
const FRONT =
  "M0 790 60 750 120 778 180 720 240 782 300 730 360 800 420 742 480 806 540 760 600 820 660 770 720 830 780 782 840 840 900 790 960 845 1020 800 1080 850 1140 810 1200 860 1260 818 1320 865 1380 830 1440 872 1500 840 1560 875 1600 860 1600 900 0 900Z";

const ROCK_LEFT =
  "M0 900 0 690 44 682 78 718 120 638 162 674 206 598 252 656 296 608 332 692 372 658 406 742 452 718 484 802 524 842 562 900Z";

function Ridge({
  d,
  fill,
  stroke,
  opacity = 1,
  className,
}: {
  d: string;
  fill: string;
  stroke?: string;
  opacity?: number;
  className?: string;
}) {
  return (
    <path
      d={d}
      fill={fill}
      stroke={stroke}
      strokeWidth={stroke ? 1 : 0}
      opacity={opacity}
      className={className}
      vectorEffect="non-scaling-stroke"
    />
  );
}

export function Terrain({
  variant = "range",
  className,
  tone = "night",
}: {
  variant?: "range" | "flanks";
  className?: string;
  tone?: "night" | "ice";
}) {
  const light = tone === "ice";
  return (
    <div className={clsx("pointer-events-none overflow-hidden", className)} aria-hidden="true">
      <svg viewBox="0 0 1600 900" preserveAspectRatio="none" className="h-full w-full">
        <defs>
          <linearGradient id={`terrain-far-${tone}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={light ? "#5c778f" : "#22374b"} />
            <stop offset="64%" stopColor={light ? "#344b61" : "#101d2b"} />
            <stop offset="100%" stopColor={light ? "#1c2c3d" : "#060b13"} />
          </linearGradient>
          <linearGradient id={`terrain-mid-${tone}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={light ? "#3c546a" : "#162739"} />
            <stop offset="58%" stopColor={light ? "#22364a" : "#0b1622"} />
            <stop offset="100%" stopColor={light ? "#132131" : "#04080e"} />
          </linearGradient>
          <linearGradient id={`terrain-front-${tone}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={light ? "#233648" : "#0b1622"} />
            <stop offset="52%" stopColor={light ? "#13202f" : "#050a11"} />
            <stop offset="100%" stopColor="#050a11" />
          </linearGradient>
          <linearGradient id={`terrain-mist-${tone}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={light ? "rgba(220,234,244,0)" : "rgba(140,180,210,0)"} />
            <stop offset="52%" stopColor={light ? "rgba(220,234,244,0.28)" : "rgba(130,176,208,0.12)"} />
            <stop offset="100%" stopColor={light ? "rgba(220,234,244,0)" : "rgba(130,176,208,0)"} />
          </linearGradient>
          <radialGradient id={`terrain-haze-${tone}`} cx="0.5" cy="0.42" r="0.6">
            <stop offset="0%" stopColor={light ? "rgba(236,246,252,0.5)" : "rgba(120,175,215,0.16)"} />
            <stop offset="100%" stopColor="rgba(0,0,0,0)" />
          </radialGradient>
        </defs>

        {variant === "range" ? (
          <g>
            <rect x="0" y="260" width="1600" height="640" fill={`url(#terrain-haze-${tone})`} />
            <Ridge d={FAR} fill={`url(#terrain-far-${tone})`} stroke="rgba(205,231,247,0.16)" opacity={0.86} />
            <rect x="0" y="470" width="1600" height="250" fill={`url(#terrain-mist-${tone})`} />
            <Ridge d={MID} fill={`url(#terrain-mid-${tone})`} stroke="rgba(205,231,247,0.13)" />
            <rect x="0" y="650" width="1600" height="160" fill={`url(#terrain-mist-${tone})`} opacity={0.8} />
            <Ridge d={FRONT} fill={`url(#terrain-front-${tone})`} stroke="rgba(205,231,247,0.08)" />
          </g>
        ) : (
          <g>
            <rect x="0" y="0" width="1600" height="900" fill={`url(#terrain-haze-${tone})`} opacity={0.5} />
            <Ridge d={FAR} fill={`url(#terrain-far-${tone})`} opacity={0.32} />
            <g>
              <Ridge d={ROCK_LEFT} fill={`url(#terrain-mid-${tone})`} stroke="rgba(218,238,250,0.18)" />
              <path d="M0 900 0 690 44 682 78 718 120 638 162 674 206 598 252 656 296 608 332 692 372 658 406 742 452 718 484 802 524 842 562 900Z" fill="rgba(5,10,17,0.32)" transform="translate(0,26)" />
              <g transform="translate(1600,0) scale(-1,1)">
                <Ridge d={ROCK_LEFT} fill={`url(#terrain-front-${tone})`} stroke="rgba(218,238,250,0.14)" />
              </g>
              <path d="M300 900 380 792 460 852 560 918Z" fill="#050a11" />
            </g>
          </g>
        )}
      </svg>
    </div>
  );
}
