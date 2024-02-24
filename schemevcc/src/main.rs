use cryptocryptid::measuresvcc;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use rand_core::{OsRng};

fn main(){
    
    let g0 = RISTRETTO_BASEPOINT_POINT; // g0 is the generator used for the public key of the game master.
    let mut csprng = OsRng;	
    let n = 108;
    let d = 5; // number of players
    let genplayers = vec![g0; d];
    let genmaster = g0;
    let clueforms = vec![0, 0, 1, 1, 1]; // two different forms of clue: 0 and 1.
    let iter = 10; // Average over iter iterations.
    measuresvcc(&mut csprng, genmaster, genplayers, clueforms, n, iter);  				
}
