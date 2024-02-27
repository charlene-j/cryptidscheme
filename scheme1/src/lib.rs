mod zkp;

pub use crate::zkp::*;

#[cfg(test)]
mod tests{
     use rand_core::OsRng;
     use rand::{distributions::{Distribution, Uniform}};
     use curve25519_dalek::{ristretto::RistrettoPoint, constants::RISTRETTO_BASEPOINT_POINT, traits::Identity}; 
     use super::zkp::{buildclue, genclue, openclue, algoanswer, play, verify};

    #[test]
    // It tests if the algorithm Openclue open the correct clue, if the algorithm Play build a correct proof and if the algorithm Verify returns true.
    fn test1cc1(){
    
        let g0 = RISTRETTO_BASEPOINT_POINT; // g0 is the generator used to build the public key of a player.
        let mut csprng = OsRng; 
        let a = vec![RistrettoPoint::identity(), RISTRETTO_BASEPOINT_POINT]; // a is the encoding vector of true and false in RistrettoPoint.
        let n = 108; // n is the number of cell.
        
        let clue = buildclue((&a).to_vec(), n);
    
        let keyc = genclue(&mut csprng, g0, (&clue).to_vec());                   
        let pc = keyc.0; //pc = (pk, E[i]=(c1[i], c2[i]) where i belong to {0,...,n-1}, E[i] = Enc_pk(clue[i]).
        let sc = keyc.1; //sc = sk.

        let open = openclue((&pc).to_vec(), sc);
        assert!(open == clue, "The open clue is not equal to the clue.");
        
        // It generates a random cryptid habitat.
        let between = Uniform::from(0..n);
        let mut rng = rand::thread_rng();
        let j = between.sample(&mut rng); 
        
        let answer = algoanswer((&a).to_vec(), (&clue).to_vec(), j);
     
        let proof = play(&mut csprng, g0, (&a).to_vec(), (&pc).to_vec(), sc, j, answer);
        let b = verify(g0, (&a).to_vec(), proof, (&pc).to_vec(), j, answer);
        assert!(b == true, "Verify is false."); 
    }
    
    #[test]
    // It tests if the player give an incorrect answer, implies that the algorithm Verify returns false.
    fn test2cc1(){
    
        let g0 = RISTRETTO_BASEPOINT_POINT; // g0 is the generator used to build the public key of a player.
        let mut csprng = OsRng; 
        let a = vec![RistrettoPoint::identity(), RISTRETTO_BASEPOINT_POINT]; // a is the encoding vector of true and false in RistrettoPoint.
        let n = 108; // n is the number of cell.
        
        let clue = buildclue((&a).to_vec(), n);
    
        let keyc = genclue(&mut csprng, g0, (&clue).to_vec());                   
        let pc = keyc.0; // pc = (pk, c1[0], c2[0], c1[1], c2[1], ..., c1[n-1], c2[n-1]).
        let sc = keyc.1; // sc = sk.

        let open = openclue((&pc).to_vec(), sc);
        assert!(open == clue, "The open clue is not equal to the clue.");
        
        // It generates a random cryptid habitat.
        let between = Uniform::from(0..n);
        let mut rng = rand::thread_rng();
        let j = between.sample(&mut rng); 
        
        let answer = algoanswer((&a).to_vec(), (&clue).to_vec(), j);
        
        let badanswer: usize;
        if answer == 1{
            badanswer = 0;
        }
        else {
            badanswer = 1;
        }
        
        let proof = play(&mut csprng, g0, (&a).to_vec(), (&pc).to_vec(), sc, j, badanswer);
        let b = verify(g0, (&a).to_vec(), proof, (&pc).to_vec(), j, badanswer);
        assert!(b == false, "Verify is true."); 
    }     
}
