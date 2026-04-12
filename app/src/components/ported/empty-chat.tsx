import { MessageCircle } from "lucide-react"

export function EmptyChat() {
  return (
    <div className="flex h-full flex-col items-center justify-center text-center">
      <div className="rounded-full bg-secondary p-6">
        <MessageCircle className="h-12 w-12 text-muted-foreground" />
      </div>
      <h2 className="mt-6 text-xl font-semibold text-foreground">
        Select a conversation
      </h2>
      <p className="mt-2 max-w-sm text-muted-foreground">
        Choose a conversation from the sidebar to start messaging
      </p>
    </div>
  )
}
