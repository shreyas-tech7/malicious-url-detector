import { useRef, type KeyboardEvent } from "react";

export type ScanMode = "url" | "file";

type Tab = {
  id: ScanMode;
  label: string;
  /** Sits under the label; says what the tab actually scans. */
  hint: string;
};

export const SCAN_TABS: Tab[] = [
  { id: "url", label: "URL", hint: "Score a link" },
  { id: "file", label: "File signature", hint: "Look up a hash" },
];

export const tabId = (mode: ScanMode) => `scan-tab-${mode}`;
export const panelId = (mode: ScanMode) => `scan-panel-${mode}`;

type ScanTabsProps = {
  value: ScanMode;
  onChange: (mode: ScanMode) => void;
};

/**
 * Tabs per the ARIA authoring practices: one stop in the page tab order via a
 * roving tabindex, arrow keys to move between tabs, and Home/End to jump.
 *
 * Selection follows focus. That pattern is only appropriate when revealing a
 * panel is cheap and side-effect free, which holds here — both panels are
 * already mounted and switching does not refetch anything.
 */
export function ScanTabs({ value, onChange }: ScanTabsProps) {
  const refs = useRef<Partial<Record<ScanMode, HTMLButtonElement | null>>>({});
  const index = SCAN_TABS.findIndex((t) => t.id === value);

  const focusTab = (next: number) => {
    const tab = SCAN_TABS[next];
    onChange(tab.id);
    refs.current[tab.id]?.focus();
  };

  const onKeyDown = (e: KeyboardEvent<HTMLButtonElement>) => {
    const last = SCAN_TABS.length - 1;
    switch (e.key) {
      case "ArrowRight":
        focusTab(index === last ? 0 : index + 1);
        break;
      case "ArrowLeft":
        focusTab(index === 0 ? last : index - 1);
        break;
      case "Home":
        focusTab(0);
        break;
      case "End":
        focusTab(last);
        break;
      default:
        return;
    }
    // Only reached when a key was handled; keeps Home/End from scrolling.
    e.preventDefault();
  };

  return (
    <div
      role="tablist"
      aria-label="What to scan"
      className="relative grid grid-cols-2 rounded-xl border border-line-strong bg-surface-1 p-1 shadow-card"
    >
      {/*
       * The moving pill is one element that translates, rather than a
       * background toggled on each tab. Sliding it is what makes the control
       * read as a single switch; `p-1` on the track and a matching inset here
       * mean translateX(100%) lands exactly on the second column.
       */}
      <span
        aria-hidden="true"
        style={{ transform: `translateX(${index * 100}%)` }}
        className="pointer-events-none absolute inset-y-1 left-1 w-[calc(50%-0.25rem)] rounded-lg bg-surface-2 ring-1 ring-inset ring-line-strong transition-transform duration-300 ease-out"
      />

      {SCAN_TABS.map((tab) => {
        const selected = tab.id === value;
        return (
          <button
            key={tab.id}
            ref={(el) => {
              refs.current[tab.id] = el;
            }}
            id={tabId(tab.id)}
            role="tab"
            type="button"
            aria-selected={selected}
            aria-controls={panelId(tab.id)}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(tab.id)}
            onKeyDown={onKeyDown}
            className={`relative z-10 cursor-pointer rounded-lg px-4 py-2.5 text-center transition-colors duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-slate-300 ${
              selected ? "text-fg-strong" : "text-fg-muted hover:text-fg"
            }`}
          >
            <span className="block text-sm font-medium">{tab.label}</span>
            <span className="mt-0.5 block text-[0.6875rem] text-fg-faint">
              {tab.hint}
            </span>
          </button>
        );
      })}
    </div>
  );
}
