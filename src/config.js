// Keep accepted intervals below Node's signed 32-bit millisecond timer limit.
export function backupIntervalHours(value) {
  const hours = Number(value ?? 24);
  if (!Number.isInteger(hours) || hours < 0 || hours > 168)
    throw new Error(
      "Backup interval must be 0 (disabled) or 1–168 whole hours.",
    );
  return hours;
}
