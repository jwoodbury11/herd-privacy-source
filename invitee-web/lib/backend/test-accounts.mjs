const TEST_ACCOUNT_PHONE_PREFIX = "+1415555010";

const TEST_ACCOUNT_NAMES = Object.freeze([
  "One Anderson",
  "Two Brown",
  "Three Davis",
  "Four Garcia",
  "Five Johnson",
  "Six Miller",
  "Seven Smith",
  "Eight Taylor",
  "Nine Wilson",
]);

export function testAccountNameForAlias(alias) {
  if (typeof alias !== "string" || !/^[1-9]$/u.test(alias.trim())) return null;
  return TEST_ACCOUNT_NAMES[Number(alias.trim()) - 1];
}

export function testAccountNameForPhoneNumber(phoneNumber) {
  if (typeof phoneNumber !== "string") return null;
  const match = /^\+1415555010([1-9])$/u.exec(phoneNumber);
  return match ? testAccountNameForAlias(match[1]) : null;
}

export function testAccountPhoneNumberForAlias(alias) {
  if (typeof alias !== "string" || !/^[1-9]$/u.test(alias.trim())) return null;
  return `${TEST_ACCOUNT_PHONE_PREFIX}${alias.trim()}`;
}

export function isTestAccountPhoneNumber(phoneNumber) {
  return typeof phoneNumber === "string" && /^\+1415555010[1-9]$/u.test(phoneNumber);
}
