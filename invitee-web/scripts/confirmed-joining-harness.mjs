import { startBrowserAcceptanceHarness } from "./browser-acceptance-harness.mjs";

// Isolated, in-memory backend for the native actor/observer regression.
// All invitation providers are mocked by the acceptance harness.
const harness = await startBrowserAcceptanceHarness({ port: 8789 });
try {
  for (const digit of ["2", "3", "4", "5"]) {
    const auth = await fetch(new URL("/api/auth/request-code", harness.baseUrl), {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ phoneNumber: digit }),
    });
    if (!auth.ok) throw new Error(`Could not authenticate test actor ${digit}`);
    const { accessToken } = await auth.json();
    const headers = { authorization: `Bearer ${accessToken}`, "content-type": "application/json" };
    const listing = await fetch(new URL("/api/events", harness.baseUrl), { headers });
    const event = (await listing.json()).events.find(({ id }) => id === harness.scenario.eventId);
    const reply = await fetch(new URL(`/api/invites/${event.inviteToken}/ballot`, harness.baseUrl), {
      method: "PUT", headers,
      body: JSON.stringify({ response: "going", minimumParticipants: digit === "2" ? 6 : 2, requiredGroups: [] }),
    });
    if (!reply.ok) throw new Error(`Could not seed test actor ${digit}`);
  }
  await harness.database.prepare("UPDATE events SET event_date = ?, rsvp_deadline = ? WHERE id = ?")
    .bind(new Date(Date.now() - 3600_000).toISOString(), new Date(Date.now() - 7200_000).toISOString(), harness.scenario.eventId).run();
  console.log("Native confirmed-joining fixture ready at http://127.0.0.1:8789");
  await new Promise((resolve) => {
    process.once("SIGINT", resolve);
    process.once("SIGTERM", resolve);
  });
} finally {
  await harness.stop();
}
