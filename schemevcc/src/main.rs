use rand_core::OsRng;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use cryptocryptid::measurementsvcc;

fn main(){
    
    let mut csprng = OsRng;
    let g0 = RISTRETTO_BASEPOINT_POINT; // g0 is the generator used to build the public key of the game master.	
    let n = 108;
    let d = 5; // d is the number of players.
    let genplayers = vec![g0; d];
    let genmaster = g0;
    let clueforms = vec![0, 0, 1, 1, 1]; // There are two different forms of clue: (Tj, Tk, bottom) or (bottom, bottom, P) where P in Pj.
    println!("Performance measurements for {:?} players:", d); // Test of performances on iter iterations. 
    let iter = 10;
    measurementsvcc(&mut csprng, genmaster, genplayers, clueforms, n, iter);  				
}
