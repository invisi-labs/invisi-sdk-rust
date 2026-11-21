/** Regenerate deterministic public test fixtures from the matching Core checkout. */
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const core = resolve(process.argv[2] ?? resolve(root, '../invisi-core'));
const manifest = JSON.parse(readFileSync(resolve(core, 'circuits/credit/manifest.json'), 'utf8'));
assert(manifest.complete && manifest.version === 8 && manifest.formatVersion === 9,
    'Current uint128 grant-ID Core release required');
const source = async (name) => import(pathToFileURL(resolve(core, 'scripts', name)).href);
const { createCreditLifecycleFixtures } = await source('credit-lifecycle-fixtures.mjs');
const { makeCreditInitialPaymentFixtures } = await source('credit-initial-payment-fixtures.mjs');
const { creation, draw, update } = await createCreditLifecycleFixtures({
    feeRecipient: '0x4444444444444444444444444444444444444444', feeAmount: 1n,
});
const { initialPayment } = await makeCreditInitialPaymentFixtures();
const families = {
    create_credit: creation,
    credit_draw_slots1: draw,
    credit_update: update,
    create_credit_initial_payment: initialPayment,
};
const select = (fixture) => Object.fromEntries(
    ['context', 'params', 'deliveries', 'publicInputs', 'witness'].map((key) => [key, fixture[key]])
);
const write = (path, value) => writeFileSync(resolve(root, path),
    JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item, 2) + '\n');
const highLevel = {};
for (const [name, fixture] of Object.entries(families).slice(0, 3)) {
    const { witness: _, ...publicData } = select(fixture);
    highLevel[name] = {
        ...publicData,
        ...(name === 'create_credit' ? { state: fixture.creditState } : {}),
    };
}
write('tests/fixtures/credit-highlevel.json', highLevel);
write('testdata/initial-payment-fixture.json', select(initialPayment));
for (const path of [
    'assets/prover/testdata/current-proving.json',
    'crates/invisi-sdk-prover/assets/prover/testdata/current-proving.json',
]) {
    const data = JSON.parse(readFileSync(resolve(root, path), 'utf8'));
    for (const [name, fixture] of Object.entries(families)) {
        const entry = { label: name, name, target: 'evm',
            witness: fixture.witness, publicInputs: fixture.publicInputs };
        const index = data.fixtures.findIndex((item) => item.name === name);
        if (index < 0) data.fixtures.push(entry);
        else data.fixtures[index] = entry;
    }
    write(path, data);
}
console.log('Generated current Core Credit fixtures, including fee and initial-payment cases');
