use rand_core::OsRng;
use curve25519_dalek::{ristretto::RistrettoPoint, constants::RISTRETTO_BASEPOINT_POINT, traits::Identity}; 
use cryptocryptid::measurementscc1;
   
fn main(){

    let mut csprng = OsRng; 
    let g0 = RISTRETTO_BASEPOINT_POINT; // g0 is the generator used to build the public key of a player
    let a = vec![RistrettoPoint::identity(), RISTRETTO_BASEPOINT_POINT]; // a is the encoding vector of true and false in RistrettoPoint.
    let n = 108;
    println!("Performance measurements:"); // Test of performances on iter iterations.    
    let iter = 10;
    measurementscc1(&mut csprng, g0, (&a).to_vec(), n, iter);     
} 
