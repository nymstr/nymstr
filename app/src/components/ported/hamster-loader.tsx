interface HamsterLoaderProps {
  message?: string;
  /** Font-size in px that scales the whole hamster+wheel. Default 14. */
  sizePx?: number;
}

export function HamsterLoader({ message, sizePx }: HamsterLoaderProps) {
  return (
    <div className="flex flex-col items-center justify-center gap-6">
      <div
        aria-label="Orange and tan hamster running in a metal wheel"
        role="img"
        className="wheel-and-hamster"
        style={sizePx ? { fontSize: `${sizePx}px` } : undefined}
      >
        <div className="wheel" />
        <div className="hamster">
          <div className="hamster__body">
            <div className="hamster__head">
              <div className="hamster__ear" />
              <div className="hamster__eye" />
              <div className="hamster__nose" />
            </div>
            <div className="hamster__limb hamster__limb--fr" />
            <div className="hamster__limb hamster__limb--fl" />
            <div className="hamster__limb hamster__limb--br" />
            <div className="hamster__limb hamster__limb--bl" />
            <div className="hamster__tail" />
          </div>
        </div>
        <div className="spoke" />
      </div>
      {message && <p className="text-sm text-muted-foreground">{message}</p>}
    </div>
  );
}
