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
	
        // It defines a random cell
        let cj = randomcell((&t).to_vec(), (&p).to_vec(), 13); // 13 is the number of properties of the cell.
        let tj = cj.0;
        let pj = cj.1;
    
        for i in 0..4{

            let clue = buildclue((&t).to_vec(), (&p).to_vec(), bottom, tj, (&pj).to_vec(), i);
            let keyc = genclue(&mut csprng, g0, (&clue).to_vec());               
            let pc = keyc.0; //pc = (pk, c11, c21, c12, c22, c13, c23)
            let sc = keyc.1; //sc = sk

            let open = openclue((&pc).to_vec(), sc);
            assert!(open == (&clue).to_vec(), "Open clue is not equal to clue");
            
            let answer = algoanswer(bottom, (&clue).to_vec(), tj, (&pj).to_vec());
            
            if i == 0 || i == 1{
                assert!(answer == 1, "Bad answer");
            }
            else{
                assert!(answer == 0, "Bad answer");
            }
            
            let proof = play(&mut csprng, g0, (&pc).to_vec(), sc, tj, (&pj).to_vec(), answer);
            let b = verify(g0, proof, (&pc).to_vec(), tj, (&pj).to_vec(), answer);
            assert!(b == true, "Verify is false");	
        }
    }
    #[test] // 
    // Same as testzkp1 except that it tests if the player give a bad answer implies that the algorithm Verify returns false.
    fn test2cc2(){ 

        // Generation of properties and map and cell.
        let mut csprng = OsRng;	
        let g0 = RISTRETTO_BASEPOINT_POINT; // g0 is the generator used in the public key of the player.
        let c = typesandproperties(&mut csprng); // Random generation of five types and fourteen properties in RistrettoPoint.
        let t = c.0; // Vector of five types.
        let p = c.1; // Vector of fourteen properties.
        let bottom = c.2; 
	
        // It defines a random cell
        let cj = randomcell((&t).to_vec(), (&p).to_vec(), 13); // 13 is the number of properties of the cell.
        let tj = cj.0;
        let pj = cj.1;
    
        for i in 0..4{

            let clue = buildclue((&t).to_vec(), (&p).to_vec(), bottom, tj, (&pj).to_vec(), i);
            let keyc = genclue(&mut csprng, g0, (&clue).to_vec());               
            let pc = keyc.0; // pc = (pk, c11, c21, c12, c22, c13, c23).
            let sc = keyc.1; // sc = sk.

            let open = openclue((&pc).to_vec(), sc);
            assert!(open == (&clue).to_vec(), "The open clue is not equal to clue");
            
            let answer = algoanswer(bottom, (&clue).to_vec(), tj, (&pj).to_vec());
            let mut badanswer = 2;
            
            if answer == 0{
                badanswer = 1;
            }
            if answer == 1{
                badanswer = 0;
            }
             
            let proof = play(&mut csprng, g0, (&pc).to_vec(), sc, tj, (&pj).to_vec(), badanswer);
            let b = verify(g0, proof, (&pc).to_vec(), tj, (&pj).to_vec(), badanswer);
            assert!(b == false, "Verify is true");
        }
    }
}
