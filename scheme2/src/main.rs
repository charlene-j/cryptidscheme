use rand_core::OsRng;
use cryptocryptid::measurementscc2;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;

fn main(){  
    let mut csprng = OsRng;	
    let g0 = RISTRETTO_BASEPOINT_POINT; // g0 is the generator used for the public key of the player.
    println!("Performance measurements:"); // Test of performances on iter iterations 
    let iter = 10;
    measurementscc2(&mut csprng, g0, iter);					
}
