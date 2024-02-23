use cryptocryptid::{typesandproperties, buildrandomclue, randomcell, schemecc2, measurestimeandsize, funanswer};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use rand_core::{OsRng};

fn main(){ 
    println!("\nExample of use of the algorithms GenClue, Openclue, Answer, Play and Verify on two different forms of clue and two different answer for a random cell: \n"); 
    // Setup of properties and map
    let mut csprng = OsRng;	
    let g0 = RISTRETTO_BASEPOINT_POINT; // g0 is the generator used in the public key of the player.
    let c = typesandproperties(&mut csprng); // random generation of five types and fourteen properties in RistrettoPoint.
    let t = c.0; // vector of five types.
    let p = c.1; // vector of fourteen properties.
    let bottom = c.2; 
	
    // It defines a random cell
    let cj = randomcell((&t).to_vec(), (&p).to_vec(), 13); // 13 is the number of properties of the cell.
    let tj = cj.0;
    let pj = cj.1;
    
    for i in 0..4{
        let vecstr = ["(Tj, Tk, bottom):", "(bottom, bottom, P) where P belongs to Pj:", "(Tl, Tk, bottom) where Tl != Tj and Tk != Tj:", "(bottom, bottom, P) where P does not belong to Pj:"];
        println!("{}", vecstr[i]);
        let clue = buildrandomclue((&t).to_vec(), (&p).to_vec(), bottom, tj, (&pj).to_vec(), i);
        let answer = funanswer(bottom, (&clue).to_vec(), tj, (&pj).to_vec());
        schemecc2(& mut csprng, g0, (&clue).to_vec(), tj, (&pj).to_vec(), answer);
    }
    
    println!("Performance measurements:"); //Test of performance over iter iterations 
    let iter = 10;
    measurestimeandsize(&mut csprng, g0, iter);					
}
