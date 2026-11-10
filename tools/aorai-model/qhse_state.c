/*
 * Illustrative C state-machine model of the QHS-E verification order.
 *
 * This is NOT a translation of the Rust verifier. It models the required
 * ordering (header, leaf index, checksum, WOTS, Merkle path, accept) so the
 * Frama-C/AORAI temporal checker can be exercised on the same sequence.
 */

#include <stdbool.h>
#include <stdint.h>

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1; */
int qhse_parse_header(uint8_t version)
{
    return version == 1 || version == 2 || version == 3;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1; */
int qhse_check_leaf(uint16_t leaf)
{
    return leaf < 4096;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1; */
int qhse_check_checksum(bool ok)
{
    return ok;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1; */
int qhse_verify_wots(bool ok)
{
    return ok;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1; */
int qhse_verify_merkle(bool ok)
{
    return ok;
}

/*@ assigns \nothing;
    ensures \result == 0; */
int qhse_accept(void)
{
    return 0;
}

/*@ assigns \nothing;
    ensures \result == 0 || \result == 1; */
int qhse_verify(uint8_t version, uint16_t leaf, bool checksum_ok, bool wots_ok,
                bool merkle_ok)
{
    if (!qhse_parse_header(version)) {
        return 1;
    }
    if (!qhse_check_leaf(leaf)) {
        return 1;
    }
    if (!qhse_check_checksum(checksum_ok)) {
        return 1;
    }
    if (!qhse_verify_wots(wots_ok)) {
        return 1;
    }
    if (!qhse_verify_merkle(merkle_ok)) {
        return 1;
    }
    return qhse_accept();
}

/*@ assigns \nothing; */
int main(void)
{
    return qhse_verify(1, 0, true, true, true);
}
