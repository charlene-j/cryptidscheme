use cryptocryptid::{typesandproperties,buildrandomclue,randomcell,schemecc2,mesuretimeandsize,funanswer}; //gencell};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use rand_core::{OsRng};

fn main(){ //-> std::io::Result<(),io::Error> {
    
    // Setup of properties and map
    let g0 = RISTRETTO_BASEPOINT_POINT; // generator used in the public key of the player
    let mut csprng = OsRng;	
    let c = typesandproperties(&mut csprng); // random generation of 5 types and 14 properties in a RistrettoPoint
    let t = c.0; // vector of 5 elements
    let p = c.1; // vector of 14 elements
	
    // Defines one specific cell
    //let prop = vec![0,1,2,3,4,5,6,7,8,9,10,11,13]; // prop correspond to the cell with the properties prop
    //let cj = gencell((&t).to_vec(),(&p).to_vec(),id,4,prop); // we built a cell with the type 4 and the properties prop
    //let tj = cj.0; 
    //let pj = cj.1;
	
    // Defines a random committed cell
    let cj = randomcell((&t).to_vec(),(&p).to_vec());
    let tj = cj.0;
    let pj = cj.1;
	
    // Defines different form of random clues
    let i = 3; 
    let clue = buildrandomclue((&t).to_vec(),(&p).to_vec(),tj,(&pj).to_vec(),i);
    
    let answer = funanswer((&clue).to_vec(),tj,(&pj).to_vec());
    
    /*let badanswer: usize;
    if answer == 0{
        badanswer = 1;
    }
    else{
    	badanswer = 0;	
    }*/
    
    // Runs the algorithm of cc2
    schemecc2(& mut csprng,g0,(&clue).to_vec(),tj,(&pj).to_vec(),answer);
   
    // Calculates a mean on a number of iter iterations of running time of the algorithms genclue, openclue, play and verify
    let iter = 500;
    mesuretimeandsize(&mut csprng,g0,iter);					
}
