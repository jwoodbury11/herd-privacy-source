/**
 * Opens every committed response independently and omits values that fail
 * authenticated decryption or private-response validation.
 *
 * The caller receives only successfully opened responses. Rejection reasons
 * and source indexes intentionally never cross the confidential-evaluator
 * boundary, so an invalid envelope is indistinguishable from a nonresponse.
 *
 * @template Input
 * @template Output
 * @param {readonly Input[]} values
 * @param {(value: Input) => Promise<Output>} open
 * @returns {Promise<Output[]>}
 */
export async function openValidPrivateResponses(values, open) {
  const settled = await Promise.allSettled(values.map((value) => open(value)));
  return settled.flatMap((result) =>
    result.status === "fulfilled" ? [result.value] : [],
  );
}
