const paths = {
  home: "M3 10 12 3l9 7M5 9v12h5v-7h4v7h5V9",
  upload: "M12 16V3m-5 5 5-5 5 5M4 16v5h16v-5",
  download: "M12 3v13m-5-5 5 5 5-5M4 17v4h16v-4",
  folder: "M3 7V5h6l3 3h9v12H3V7Z",
  file: "M14 3H5v18h14V8l-5-5Zm0 0v5h5M8 12h8M8 16h6",
  share: "M9 15 20 4m-8 0h8v8M7 4H4v16h16v-3",
  clock: "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0ZM12 7v5l3 2",
  shield: "M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3ZM8 12l3 3 5-6",
  info: "M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0ZM12 11v6M12 7v.1",
  cloud: "M7 18H6a4 4 0 0 1-.7-7.94A7 7 0 0 1 19 9a4.5 4.5 0 0 1 0 9h-2M9 15l3 3 3-3M12 18V9",
  arrow: "M4 12h16m-6-6 6 6-6 6",
  plus: "M12 5v14M5 12h14",
  logout: "M9 4H4v16h5M10 12h11m-5-5 5 5-5 5",
  lock: "M6 10h12v11H6V10Zm2 0V7a4 4 0 0 1 8 0v3M12 14v3",
  users: "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0Zm5 8a4 4 0 0 1 4 4v2M17 3a4 4 0 0 1 0 8",
  check: "M5 12l4 4L19 6",
  refresh: "M20 7v5h-5M4 17v-5h5M5.5 8a7.5 7.5 0 0 1 12.4-3L20 8M4 16l2.1 3a7.5 7.5 0 0 0 12.4-3",
};

export default function Icon({ name }) {
  return (
    <svg className="ui-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
      <path d={paths[name]} />
    </svg>
  );
}
