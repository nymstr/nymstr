import { useState } from "react";
import { Button } from "@/components/shadcn/button";
import { Input } from "@/components/shadcn/input";
import { Avatar, AvatarFallback } from "@/components/shadcn/avatar";
import { FieldGroup, Field, FieldLabel } from "@/components/shadcn/field";
import { ArrowLeft, Copy, Check, LogOut, Key, User as UserIcon } from "lucide-react";
import { useAuthStore } from "@/stores/authStore";
import { useChatStore } from "@/stores/chatStore";
import { useGroupStore } from "@/stores/groupStore";
import * as api from "@/services/api";
import { showToast } from "@/hooks/useToast";

interface SettingsPanelProps {
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

export function SettingsPanel({ onClose }: SettingsPanelProps) {
  const user = useAuthStore((s) => s.user);
  const authLogout = useAuthStore((s) => s.logout);
  const resetChat = useChatStore((s) => s.reset);
  const resetGroups = useGroupStore((s) => s.reset);

  const [copied, setCopied] = useState(false);
  const [loggingOut, setLoggingOut] = useState(false);

  if (!user) return null;

  const publicKey = user.publicKey || "";

  const handleCopyKey = async () => {
    if (!publicKey) return;
    await navigator.clipboard.writeText(publicKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleLogout = async () => {
    setLoggingOut(true);
    try {
      await api.logout();
    } catch (err) {
      console.error("[Settings] logout error:", err);
    } finally {
      resetChat();
      resetGroups();
      authLogout();
      showToast.info("Logged out");
      setLoggingOut(false);
    }
  };

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-3 border-b border-border px-4 py-3">
        <Button
          variant="ghost"
          size="icon"
          onClick={onClose}
          className="text-muted-foreground hover:text-foreground md:hidden"
        >
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <h2 className="text-lg font-semibold text-foreground">Settings</h2>
      </div>

      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-md space-y-8">
          <div className="flex flex-col items-center gap-4">
            <Avatar className="h-20 w-20">
              <AvatarFallback className="text-2xl">
                {initials(user.displayName || user.username)}
              </AvatarFallback>
            </Avatar>
            <div className="text-center">
              <p className="font-medium text-foreground">
                {user.displayName || user.username}
              </p>
              <p className="text-sm text-muted-foreground">@{user.username}</p>
            </div>
          </div>

          <FieldGroup>
            <Field>
              <FieldLabel className="flex items-center gap-2">
                <UserIcon className="h-4 w-4" />
                Username
              </FieldLabel>
              <Input value={user.username} readOnly className="font-mono text-sm" />
              <p className="mt-1.5 text-xs text-muted-foreground">
                Your username is permanent and cannot be changed.
              </p>
            </Field>
          </FieldGroup>

          <FieldGroup>
            <Field>
              <FieldLabel className="flex items-center gap-2">
                <Key className="h-4 w-4" />
                Public key
              </FieldLabel>
              <div className="flex gap-2">
                <Input
                  value={publicKey}
                  readOnly
                  className="flex-1 font-mono text-xs"
                />
                <Button
                  variant="outline"
                  size="icon"
                  onClick={handleCopyKey}
                  className="shrink-0"
                  disabled={!publicKey}
                >
                  {copied ? (
                    <Check className="h-4 w-4 text-emerald-500" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </Button>
              </div>
              <p className="mt-1.5 text-xs text-muted-foreground">
                Share your public key so others can verify your identity.
              </p>
            </Field>
          </FieldGroup>

          <div className="pt-4">
            <Button
              variant="outline"
              onClick={handleLogout}
              disabled={loggingOut}
              className="w-full gap-2 text-destructive hover:bg-destructive/10 hover:text-destructive"
            >
              <LogOut className="h-4 w-4" />
              {loggingOut ? "Logging out..." : "Log out"}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
