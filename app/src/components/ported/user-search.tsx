import { useState } from "react";
import { Avatar, AvatarFallback } from "@/components/shadcn/avatar";
import { Input } from "@/components/shadcn/input";
import { Button } from "@/components/shadcn/button";
import {
  Search,
  X,
  AtSign,
  Loader2,
  AlertCircle,
  MessageCircle,
} from "lucide-react";
import { useNewConversation } from "@/hooks/useNewConversation";
import { showToast } from "@/hooks/useToast";

interface UserSearchProps {
  onOpenConversation: (conversationId: string) => void;
  onClose: () => void;
}

function initials(name: string) {
  return name
    .split(" ")
    .filter(Boolean)
    .slice(0, 2)
    .map((n) => n[0]!.toUpperCase())
    .join("");
}

export function UserSearch({ onOpenConversation, onClose }: UserSearchProps) {
  const [query, setQuery] = useState("");
  const { status, error, foundUser, lookupUser, startChat, reset } =
    useNewConversation();

  const handleLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    const username = query.trim().replace(/^@/, "");
    if (!username) return;
    const user = await lookupUser(username);
    if (user && (status === "ready" || conversationAlreadyOpenable(user.username))) {
      // already-existing conversation: open immediately
      onOpenConversation(user.username);
    }
  };

  const conversationAlreadyOpenable = (_username: string) => false;

  const handleStartChat = async () => {
    if (!foundUser) return;
    const id = await startChat(foundUser.username);
    if (id) {
      showToast.success("Request sent", `@${foundUser.username}`);
      onOpenConversation(id);
    }
  };

  const handleOpenExisting = () => {
    if (!foundUser) return;
    onOpenConversation(foundUser.username);
  };

  const handleChange = (value: string) => {
    setQuery(value);
    if (status !== "idle") reset();
  };

  const isBusy = status === "querying" || status === "initiating";

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center justify-between border-b border-border px-4 py-3">
        <h2 className="text-lg font-semibold text-foreground">New Message</h2>
        <Button
          variant="ghost"
          size="icon"
          onClick={onClose}
          className="text-muted-foreground hover:text-foreground"
        >
          <X className="h-5 w-5" />
        </Button>
      </div>

      <form onSubmit={handleLookup} className="border-b border-border p-3">
        <div className="relative">
          <AtSign className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={query}
            onChange={(e) => handleChange(e.target.value)}
            placeholder="Enter username..."
            className="pl-9 bg-secondary border-0 rounded-full focus-visible:ring-1 focus-visible:ring-accent"
            autoFocus
            disabled={isBusy}
          />
        </div>
        <Button
          type="submit"
          className="mt-2 w-full"
          disabled={!query.trim() || isBusy}
          variant="outline"
        >
          {status === "querying" ? "Looking up..." : "Find user"}
        </Button>
      </form>

      <div className="flex-1 overflow-y-auto p-4">
        {status === "idle" && (
          <div className="flex flex-col items-center justify-center gap-3 px-4 py-12 text-center">
            <div className="flex h-12 w-12 items-center justify-center rounded-full bg-secondary">
              <Search className="h-6 w-6 text-muted-foreground" />
            </div>
            <p className="text-sm text-muted-foreground">
              Enter a username to find and message someone
            </p>
          </div>
        )}

        {status === "querying" && (
          <div className="flex items-center justify-center gap-2 py-12 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            <span className="text-sm">Looking up @{query}...</span>
          </div>
        )}

        {status === "not_found" && (
          <div className="flex flex-col items-center justify-center gap-2 px-4 py-12 text-center">
            <Avatar className="h-12 w-12">
              <AvatarFallback>?</AvatarFallback>
            </Avatar>
            <p className="text-sm text-muted-foreground">
              No user found for <span className="font-mono">@{query}</span>
            </p>
          </div>
        )}

        {(status === "found" || status === "ready") && foundUser && (
          <div className="flex flex-col items-center gap-4 rounded-xl border border-border bg-card p-6 text-center">
            <Avatar className="h-16 w-16">
              <AvatarFallback className="text-xl">
                {initials(foundUser.username)}
              </AvatarFallback>
            </Avatar>
            <div>
              <p className="font-medium text-foreground">
                @{foundUser.username}
              </p>
              <p className="mt-1 font-mono text-[10px] text-muted-foreground break-all">
                {foundUser.publicKey.slice(0, 40)}...
              </p>
            </div>
            {status === "ready" ? (
              <Button onClick={handleOpenExisting} className="w-full gap-2">
                <MessageCircle className="h-4 w-4" />
                Open conversation
              </Button>
            ) : (
              <Button onClick={handleStartChat} className="w-full gap-2">
                <MessageCircle className="h-4 w-4" />
                Start chat
              </Button>
            )}
          </div>
        )}

        {status === "initiating" && (
          <div className="flex items-center justify-center gap-2 py-12 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            <span className="text-sm">Establishing secure session...</span>
          </div>
        )}

        {status === "pending_handshake" && foundUser && (
          <div className="flex flex-col items-center justify-center gap-2 px-4 py-12 text-center">
            <p className="text-sm text-muted-foreground">
              Request sent. Waiting for @{foundUser.username} to accept.
            </p>
          </div>
        )}

        {status === "error" && error && (
          <div className="flex items-start gap-2 rounded-lg bg-destructive/10 p-3 text-sm text-destructive">
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>
    </div>
  );
}
