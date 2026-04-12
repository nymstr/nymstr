import { cn } from "@/lib/utils";
import type { Conversation } from "@/types";
import { Avatar, AvatarFallback } from "@/components/shadcn/avatar";
import { formatDistanceToNow } from "date-fns";
import { Users } from "lucide-react";

interface ConversationListProps {
  conversations: Conversation[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

function initials(name: string) {
  return name
    .split(" ")
    .filter(Boolean)
    .slice(0, 2)
    .map((n) => n[0]!.toUpperCase())
    .join("");
}

export function ConversationList({
  conversations,
  selectedId,
  onSelect,
}: ConversationListProps) {
  if (conversations.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-2 px-4 py-12 text-center">
        <p className="text-sm text-muted-foreground">No conversations yet</p>
        <p className="text-xs text-muted-foreground">
          Start one with the compose button above
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col">
      {conversations.map((conv) => {
        const isGroup = conv.type === "group";
        const lastAt = conv.lastMessageTime
          ? formatDistanceToNow(new Date(conv.lastMessageTime), { addSuffix: false })
          : null;

        return (
          <button
            key={conv.id}
            onClick={() => onSelect(conv.id)}
            className={cn(
              "flex items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-secondary/50",
              selectedId === conv.id && "bg-secondary",
            )}
          >
            <div className="relative">
              <Avatar className="h-12 w-12">
                <AvatarFallback>
                  {isGroup ? <Users className="h-5 w-5" /> : initials(conv.name)}
                </AvatarFallback>
              </Avatar>
              {!isGroup && (
                <span
                  className={cn(
                    "absolute bottom-0 right-0 h-3 w-3 rounded-full border-2 border-card",
                    conv.online ? "bg-emerald-500" : "bg-muted-foreground/30",
                  )}
                />
              )}
            </div>
            <div className="flex-1 overflow-hidden">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate font-medium text-foreground">
                  {conv.name}
                </span>
                <div className="flex shrink-0 items-center gap-2">
                  {lastAt && (
                    <span className="text-xs text-muted-foreground">{lastAt}</span>
                  )}
                  {conv.unreadCount > 0 && (
                    <span className="flex h-5 min-w-5 items-center justify-center rounded-full bg-accent px-1.5 text-xs font-medium text-accent-foreground">
                      {conv.unreadCount}
                    </span>
                  )}
                </div>
              </div>
              {conv.lastMessage && (
                <p className="truncate text-sm text-muted-foreground">
                  {conv.lastMessage}
                </p>
              )}
            </div>
          </button>
        );
      })}
    </div>
  );
}
