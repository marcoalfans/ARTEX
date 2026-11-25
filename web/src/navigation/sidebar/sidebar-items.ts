import {
  Activity,
  Ban,
  BellRing,
  Bot,
  Brain,
  Bug,
  ClipboardList,
  FolderOpen,
  FolderSync,
  LayoutDashboard,
  type LucideIcon,
  MessageSquare,
  Network,
  Plug,
  Radio,
  ScrollText,
  Settings2,
  ShieldAlert,
  Sparkles,
  Target,
  Terminal,
  Wrench,
} from "lucide-react";

export type NavBadge = "new" | "soon";

export interface NavSubItem {
  id: string;
  title: string;
  titleKey?: string;
  url: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

interface NavItemBase {
  id: string;
  title: string;
  titleKey?: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

export interface NavMainLinkItem extends NavItemBase {
  url: string;
  subItems?: never;
}

export interface NavMainParentItem extends NavItemBase {
  subItems: NavSubItem[];
}

export type NavMainItem = NavMainLinkItem | NavMainParentItem;

export interface NavGroup {
  id: number;
  label?: string;
  labelKey?: string;
  items: NavMainItem[];
}

/**
 * Each `titleKey` is a dotted path into the i18n JSON files (e.g. "nav.dashboard").
 * The `title` field is kept as the English fallback so non-i18n code still works.
 */
export const sidebarItems: NavGroup[] = [
  {
    id: 1,
    label: "Functions",
    labelKey: "nav.functions",
    items: [
      { id: "dashboard", title: "Dashboard", titleKey: "nav.dashboard", url: "/dashboard", icon: LayoutDashboard },
      { id: "chat", title: "Chat", titleKey: "nav.chat", url: "/chat", icon: MessageSquare },
      { id: "tasks", title: "Tasks", titleKey: "nav.tasks", url: "/function/tasks", icon: Target },
      { id: "findings", title: "Findings", titleKey: "nav.findings", url: "/function/findings", icon: Bug },
      { id: "traffic", title: "Traffic", titleKey: "nav.traffic", url: "/function/traffic", icon: Activity },
      { id: "commands", title: "Tool Execution", titleKey: "nav.toolExecution", url: "/function/commands", icon: Terminal },
      { id: "llm-records", title: "LLM Recording", titleKey: "nav.llmRecording", url: "/function/llm-records", icon: Radio },
      { id: "assets", title: "Assets", titleKey: "nav.assets", url: "/function/assets", icon: Network },
      { id: "sync", title: "Asset Sync", titleKey: "nav.assetSync", url: "/function/sync", icon: FolderSync },
      { id: "workspace", title: "Workspace", titleKey: "nav.workspace", url: "/function/workspace", icon: FolderOpen },
    ],
  },
  {
    id: 2,
    label: "System",
    labelKey: "nav.system",
    items: [
      { id: "llm", title: "LLM", titleKey: "nav.llm", url: "/system/llm", icon: Brain },
      { id: "agents", title: "Agent", titleKey: "nav.agent", url: "/system/agents", icon: Bot },
      { id: "mcp", title: "MCP", titleKey: "nav.mcp", url: "/system/mcp", icon: Plug },
      { id: "skills", title: "Skill", titleKey: "nav.skill", url: "/system/skills", icon: Sparkles },
      { id: "tools", title: "Tools", titleKey: "nav.tools", url: "/system/tools", icon: Wrench },
      { id: "notify", title: "Notifications", titleKey: "nav.notifications", url: "/system/notify", icon: BellRing },
      { id: "intercept", title: "Interception Rules", titleKey: "nav.interceptionRules", url: "/system/intercept", icon: ShieldAlert },
      { id: "asset-intercept", title: "Asset Interception", titleKey: "nav.assetInterception", url: "/system/intercept/assets", icon: Ban },
      { id: "approvals", title: "Approval Records", titleKey: "nav.approvalRecords", url: "/system/intercept/approvals", icon: ClipboardList },
      { id: "logs", title: "Logs", titleKey: "nav.logs", url: "/system/logs", icon: ScrollText },
      { id: "settings", title: "System Settings", titleKey: "nav.systemSettings", url: "/system/settings", icon: Settings2 },
    ],
  },
];
