import { useId } from "react";

export default function VaultArtwork() {
  const gradient = useId();
  return (
    <svg className="vault-artwork" viewBox="0 0 320 240" fill="none" aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id={gradient} x1="85" y1="80" x2="240" y2="215" gradientUnits="userSpaceOnUse">
          <stop stopColor="#baf3ee" /><stop offset="1" stopColor="#69c9df" />
        </linearGradient>
      </defs>
      <circle cx="161" cy="125" r="99" fill="white" fillOpacity=".08" />
      <circle cx="161" cy="125" r="78" stroke="white" strokeOpacity=".14" strokeDasharray="4 8" />
      <rect x="80" y="41" width="92" height="128" rx="14" transform="rotate(-14 80 41)" fill="#e5e7ff" />
      <rect x="124" y="32" width="94" height="129" rx="14" transform="rotate(12 124 32)" fill="white" />
      <path d="M150 67h41M150 82h31M150 98h41" stroke="#b8b5f3" strokeWidth="6" strokeLinecap="round" />
      <path d="M70 112c0-9 7-16 16-16h46l19 19h78c10 0 17 8 15 18l-10 60c-1 8-8 14-16 14H91c-8 0-15-6-16-14l-5-81Z" fill={`url(#${gradient})`} />
      <path d="m158 139-23 9v19c0 13 23 24 23 24s23-11 23-24v-19l-23-9Z" fill="white" fillOpacity=".95" />
      <path d="m148 164 7 7 14-15" stroke="#0f766e" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="247" cy="65" r="21" fill="white" />
      <path d="m238 65 6 6 12-13" stroke="#5b4ce6" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="58" cy="181" r="6" fill="#fddba8" />
      <circle cx="265" cy="162" r="5" fill="#baf3ee" />
      <path d="M53 77h12M59 71v12" stroke="#d6ccff" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}
