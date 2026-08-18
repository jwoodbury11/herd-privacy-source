export function requiredAttendeeName(fullName) {
  const parts = fullName.trim().split(/\s+/).filter(Boolean);
  const firstName = parts[0];
  if (!firstName) return "Guest";
  const lastInitial = parts.length > 1 ? parts.at(-1)?.[0] : undefined;
  return lastInitial ? `${firstName} ${lastInitial.toUpperCase()}` : firstName;
}
