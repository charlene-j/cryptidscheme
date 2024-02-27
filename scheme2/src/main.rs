use rand_core::OsRng;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use cryptocryptid::measurementscc2;

fn main(){  

    let mut csprng = OsRng;	
    let g0 = RISTRETTO_BASEPOINT_POINT; // g0 is the generator used for the public key of the player.
    println!("Performance measurements:"); // Testing the performances on iter iterations.
    let iter = 10;
    measurementscc2(&mut csprng, g0, iter);					
}
