use cryptocryptid::{typesandproperties,buildrandomclue,randomcell,schemecc2,measurestimeandsize,funanswer,random_point}; //gencell};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use rand_core::{OsRng};

fn main(){ 
    println!("It runs the algorithms GenClue, OpenClue, Play and Verify for the scheme CC2 on a random cell: \n");
    
    // Setup of properties and map
    let mut csprng = OsRng;	
    let g0 = RISTRETTO_BASEPOINT_POINT; // generator used in the public key of the player
    //let g0 = random_point(&mut csprng);
    let c = typesandproperties(&mut csprng); // random generation of 5 types and 14 properties in a RistrettoPoint
    let t = c.0; // vector of 5 elements
    let p = c.1; // vector of 14 elements
    let bottom = c.2;
    // Defines one specific cell
    //let prop = vec![0,1,2,3,4,5,6,7,8,9,10,11,13]; // prop correspond to the cell with the properties prop
    //let cj = gencell((&t).to_vec(),(&p).to_vec(),id,4,prop); // we build a cell with the type 4 and the properties prop
    //let tj = cj.0; 
    //let pj = cj.1;
	
    // Defines a random committed cell
    let cj = randomcell((&t).to_vec(),(&p).to_vec());
    let tj = cj.0;
    let pj = cj.1;
	
    // Defines different form of random clues
    let i = 3; 
    let clue = buildrandomclue((&t).to_vec(),(&p).to_vec(),bottom,tj,(&pj).to_vec(),i);
    
    let answer = funanswer(bottom, (&clue).to_vec(), tj, (&pj).to_vec());
    
    /*let badanswer: usize;
    if answer == 0{
        badanswer = 1;
    }
    else{
    	badanswer = 0;	
    }*/
    
    // It runs the algorithms for the scheme cc2
    schemecc2(& mut csprng,g0,(&clue).to_vec(),tj,(&pj).to_vec(),answer);
   
    // It calculates an average on a number of iter iterations of running time of the algorithms genclue, openclue, play and verify
    let iter = 500;
    measurestimeandsize(&mut csprng,g0,iter);					
}
