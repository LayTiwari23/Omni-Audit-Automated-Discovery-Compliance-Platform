/**
 * components/UserProfileCard.jsx
 */
import { formatToIST } from '../utils/date';

export default function UserProfileCard({ user }) {
  if (!user) {
    return (
      <div className="rounded-xl border border-gray-100 shadow-sm bg-white p-5 animate-pulse h-32" />
    );
  }

  const initials = (user.full_name || user.username || user.email || "U")
    .split(" ")
    .map((w) => w[0])
    .join("")
    .toUpperCase()
    .slice(0, 2);

  return (
    <div className="rounded-xl border border-gray-100 shadow-sm bg-white p-5 flex items-center gap-4">
      <div className="w-12 h-12 rounded-full bg-blue-600 flex items-center justify-center text-white font-bold text-lg flex-shrink-0">
        {initials}
      </div>
      <div className="min-w-0">
        <p className="font-semibold text-gray-900 truncate">
          {user.full_name || user.username || "User"}
        </p>
        <p className="text-sm text-gray-500 truncate">{user.email}</p>
        {user.created_at && (
          <p className="text-xs text-gray-400 mt-0.5">
            Member since {formatToIST(user.created_at, { day: undefined, hour: undefined, minute: undefined })}
          </p>
        )}
      </div>
    </div>
  );
}
