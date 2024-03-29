mod zkp;

pub use crate::zkp::*;

#[cfg(test)]
mod tests{
    use rand_core::{OsRng};
    use super::zkp::{typesandproperties, buildclue, randomcell, genclue, openclue, algoanswer, play, verify};
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    
    #[test] 
    // It tests if the algorithm Openclue open the correct clue, if the algorithm algoanswer returns the correct answer, if the algorithm Play build a correct proof and if the algorithm Verify returns true.
    fn test1cc2(){ 

        // Generation of types, properties and cell.
        let mut csprng = OsRng;	
        let g0 = RISTRETTO_BASEPOINT_POINT; // g0 is the generator used to build the public key of the player.
        let c = typesandproperties(&mut csprng); // Random generation of five types and fourteen properties in RistrettoPoint.
        let t = c.0; // Vector of five types.
        let p = c.1; // Vector of fourteen properties.
        let bottom = c.2; 
	
        // It defines a random cell.
        let cj = randomcell((&t).to_vec(), (&p).to_vec(), 13); // 13 is the number of properties of the cell.
        let tj = cj.0;
        let pj = cj.1;
    
        for i in 0..4{

            let clue = buildclue((&t).to_vec(), (&p).to_vec(), bottom, tj, (&pj).to_vec(), i);
            let keyc = genclue(&mut csprng, g0, (&clue).to_vec());               
            let pc = keyc.0; // pc = (pk, c1[0], c2[0], c1[1], c2[1], c1[2], c2[2]).
            let sc = keyc.1; // sc = sk.

            let open = openclue((&pc).to_vec(), sc);
            assert!(open == (&clue).to_vec(), "The open clue is not equal to the clue.");
            
            let answer: usize;
            if i == 0 || i == 1{
                answer = 1;
            }
            else{
                answer = 0;
            }
            assert!(answer == algoanswer(bottom, (&clue).to_vec(), tj, (&pj).to_vec()), "The answer is not correct.");
            
            let proof = play(&mut csprng, g0, (&pc).to_vec(), sc, tj, (&pj).to_vec(), answer);
            let b = verify(g0, proof, (&pc).to_vec(), tj, (&pj).to_vec(), answer);
            assert!(b == true, "Verify is false.");	
        }
    }
    #[test] // 
    // Same as test1cc2 except that it tests if the player give a bad answer implies that the algorithm Verify returns false.
    fn test2cc2(){ 

        // Generation of properties and map and cell.
        let mut csprng = OsRng;	
        let g0 = RISTRETTO_BASEPOINT_POINT; // g0 is the generator used in the public key of the player.
        let c = typesandproperties(&mut csprng); // Random generation of five types and fourteen properties in RistrettoPoint.
        let t = c.0; // Vector of five types.
        let p = c.1; // Vector of fourteen properties.
        let bottom = c.2; 
	
        // It defines a random cell.
        let cj = randomcell((&t).to_vec(), (&p).to_vec(), 13); // 13 is the number of properties of the cell.
        let tj = cj.0;
        let pj = cj.1;
    
        for i in 0..4{

            let clue = buildclue((&t).to_vec(), (&p).to_vec(), bottom, tj, (&pj).to_vec(), i);
            let keyc = genclue(&mut csprng, g0, (&clue).to_vec());               
            let pc = keyc.0; // pc = (pk, c1[0], c2[0], c1[1], c2[1], c1[2], c2[2]).
            let sc = keyc.1; // sc = sk.

            let open = openclue((&pc).to_vec(), sc);
            assert!(open == (&clue).to_vec(), "The open clue is not equal to the clue.");
            
            let badanswer: usize;
            if i == 0 || i == 1{
                badanswer = 0;
            }
            else{
                badanswer = 1;
            }
            let correctanswer = algoanswer(bottom, (&clue).to_vec(), tj, (&pj).to_vec());
            assert!(correctanswer == 1 - badanswer, "badanswer is not correct");
             
            let proof = play(&mut csprng, g0, (&pc).to_vec(), sc, tj, (&pj).to_vec(), badanswer);
            let b = verify(g0, proof, (&pc).to_vec(), tj, (&pj).to_vec(), badanswer);
            assert!(b == false, "Verify is true.");
        }
    }
}
