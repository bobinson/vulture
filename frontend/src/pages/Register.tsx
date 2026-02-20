import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useTranslation } from "react-i18next";
import { useAuth } from "@/lib/auth.tsx";

export function Register() {
  const { t } = useTranslation();
  const { register } = useAuth();
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [teamName, setTeamName] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    if (password.length < 8) {
      setError(t("auth.passwordTooShort"));
      return;
    }
    setLoading(true);
    try {
      await register(email, password, name, teamName || undefined);
      navigate("/");
    } catch {
      setError(t("auth.registrationFailed"));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-cream flex items-center justify-center p-4">
      <div className="w-full max-w-[360px]">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center gap-0.5 mb-3">
            <span className="text-2xl font-extrabold tracking-tight text-accent">V</span>
            <span className="text-lg font-semibold text-foreground">ulture</span>
          </div>
          <p className="text-[13px] text-muted">{t("auth.registerSubtitle")}</p>
        </div>

        <form onSubmit={handleSubmit} className="card p-6 space-y-5">
          <h2 className="text-[15px] font-semibold text-foreground">{t("auth.createAccount")}</h2>

          {error && (
            <div className="text-[12px] text-danger bg-danger/5 border border-danger/15 rounded-lg px-3 py-2">
              {error}
            </div>
          )}

          <div className="space-y-1.5">
            <label className="text-[12px] font-medium text-muted block">
              {t("auth.name")}
            </label>
            <input
              type="text"
              className="input-field"
              placeholder={t("auth.namePlaceholder")}
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              autoFocus
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-[12px] font-medium text-muted block">
              {t("auth.email")}
            </label>
            <input
              type="email"
              className="input-field"
              placeholder={t("auth.emailPlaceholder")}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
            />
          </div>

          <div className="space-y-1.5">
            <label className="text-[12px] font-medium text-muted block">
              {t("auth.password")}
            </label>
            <input
              type="password"
              className="input-field"
              placeholder={t("auth.passwordPlaceholder")}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="new-password"
              minLength={8}
            />
            <p className="text-[11px] text-muted-light">{t("auth.passwordHint")}</p>
          </div>

          <div className="space-y-1.5">
            <label className="text-[12px] font-medium text-muted block">
              {t("auth.teamName")}
              <span className="text-muted-light font-normal ml-1">({t("auth.optional")})</span>
            </label>
            <input
              type="text"
              className="input-field"
              placeholder={t("auth.teamPlaceholder")}
              value={teamName}
              onChange={(e) => setTeamName(e.target.value)}
            />
          </div>

          <button type="submit" className="btn-primary w-full !py-2" disabled={loading}>
            {loading ? (
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : (
              t("auth.createAccount")
            )}
          </button>

          <p className="text-[12px] text-center text-muted">
            {t("auth.hasAccount")}{" "}
            <Link to="/login" className="text-accent hover:text-accent-dark font-medium transition-colors">
              {t("auth.login")}
            </Link>
          </p>
        </form>
      </div>
    </div>
  );
}
