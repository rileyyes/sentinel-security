import { NavLink, Outlet } from "react-router-dom";

const nav = [
  { to: "/dashboard", label: "Dashboard" },
  { to: "/investigate", label: "Investigate Software" },
  { to: "/secure", label: "Secure Software" },
  { to: "/settings", label: "Settings" },
];

export default function Layout() {
  return (
    <div className="min-h-screen flex">
      <aside className="w-56 shrink-0 border-r border-base-600 bg-base-800 flex flex-col">
        <div className="px-4 py-4 border-b border-base-600">
          <div className="font-mono text-sm text-accent">SENTINEL</div>
          <div className="text-[11px] text-muted">Security Investigation Platform</div>
        </div>
        <nav className="flex-1 px-2 py-3 space-y-1">
          {nav.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `block px-3 py-2 rounded-md text-sm ${isActive ? "bg-accent/15 text-accent" : "text-slate-300 hover:bg-base-700"}`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="px-4 py-3 text-[11px] text-muted border-t border-base-600">
          Human decides. AI explains. Nothing here is executed.
        </div>
      </aside>
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  );
}
