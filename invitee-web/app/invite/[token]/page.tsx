import { HerdApp } from "../../page";

export default async function InvitationPage({
  params,
}: {
  params: Promise<{ token: string }>;
}) {
  const { token } = await params;
  return <HerdApp inviteToken={token} />;
}
