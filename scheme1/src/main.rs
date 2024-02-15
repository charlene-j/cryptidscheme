use cryptocryptid::{buildrandomclue,schemecc1,mesuretimeandsize,funanswer};
use curve25519_dalek::{ristretto::RistrettoPoint,constants::RISTRETTO_BASEPOINT_POINT,traits::Identity}; 
use rand_core::OsRng;
use rand::Rng;
   
fn main(){

    let g0 = RISTRETTO_BASEPOINT_POINT;
    let mut csprng = OsRng; 
    let a = vec![RistrettoPoint::identity(),RISTRETTO_BASEPOINT_POINT];
    
    // Generates a random clue
    let clue = buildrandomclue((&a).to_vec());
    
    // Generates a random index of cell
    let mut rng = rand::thread_rng();
    let j = rng.gen_range(0..108);

    // Generates the answer corresponding to the clue and the cell j
    let answer = funanswer((&a).to_vec(),(&clue).to_vec(),j);
    
    /*let mut badanswer = 2;
    if answer == 0{
    	badanswer = 1;
    }
    else{
    	badanswer = 0;
    }*/
    
    // Runs the alogrithms for the protocol cc1 
    schemecc1(& mut csprng,g0,(&a).to_vec(),(&clue).to_vec(),j,answer);
    
    // Calculates a mean of the execution time of the genclue, openclue, play and verify algorithms over a number of iterations
    let iter = 500;
    mesuretimeandsize(& mut csprng,g0,(&a).to_vec(),iter);     
} 
