mod zkp;

pub use crate::zkp::*;

#[cfg(test)]
mod tests{
    use rand_core::OsRng;
    use rand::{distributions::{Distribution, Uniform}};
    use curve25519_dalek::{constants::RISTRETTO_BASEPOINT_POINT, traits::Identity, RistrettoPoint};
    use super::zkp::{random_point, typesandproperties, buildclue, buildplayerclues, buildrandommap, genplayerclues, openclue, algoanswer, play, verify, provegame, verifygame};
    
    #[test] 
    // It test if the algorithms ProveGame builds a correct proof and if the algorithm VerifyGame returns true.
    fn test1vcc(){
    
        // Generation of properties, clues and map.
        let mut csprng = OsRng;	
        let g0 = RISTRETTO_BASEPOINT_POINT; // g0 is generator used in the public key of the player.
        let c = typesandproperties(&mut csprng); // Random generation of five types and fourteen properties in a RistrettoPoint
        let t = c.0; // vector of five elements.
        let p = c.1; // vector of fourteen elements
        let bottom = c.2;
	let n = 108; // n is the number of cell.  
        // It generates a random map.
        let map = buildrandommap((&t).to_vec(), (&p).to_vec(), n);
        let maptypes = map.0;
        let mapprop = map.1;
        
        //Generates an random cryptid habitat.
        let between = Uniform::from(0..n);
        let mut rng = rand::thread_rng();
        let j = between.sample(&mut rng);
    
        let d = 3; // d is the number of players.
        let genplayers = vec![g0; d]; // generators used for the public key of the players.
        let genmaster = g0; // generator used for the public key of the game master.
        let mut cluesforms: Vec<usize> = Vec::new(); // different forms of correct clues.
        
        let between2 = Uniform::from(0..2);
        let mut rng2 = rand::thread_rng();
        for _i in 0..d{
            cluesforms.push(between2.sample(&mut rng2));
        }
        
        let playerclues = buildplayerclues((&t).to_vec(), (&p).to_vec(), bottom, maptypes[j], (&mapprop[j]).to_vec(), (&cluesforms).to_vec());
        let keyc = genplayerclues(& mut csprng, (&genplayers).to_vec(), (&playerclues).to_vec());
        let pcplayers = keyc.0; 
        let scplayers = keyc.1;
            
        let proof = provegame(& mut csprng,(&t).to_vec(), (&p).to_vec(),  bottom, (&maptypes).to_vec(), (&mapprop).to_vec(), j, genmaster, (&genplayers).to_vec(), (&pcplayers).to_vec(), (&scplayers).to_vec());

        let pg = proof.0;
        let proof0 = proof.1;
        let proof1 = proof.2;
        let proof2 = proof.3;
        let proof3 = proof.4;
    
        let b = verifygame((&t).to_vec(), (&p).to_vec(), bottom, (&maptypes).to_vec(), (&mapprop).to_vec(), genmaster,(&genplayers).to_vec(), (&pcplayers).to_vec(), pg, proof0, proof1, proof2, proof3);
        assert!(b == (true, true, true, true), "Verify is false"); 
        
        for i in 0..d{

            let open = openclue((&pcplayers[i]).to_vec(), scplayers[i]);
            assert!(open == (&playerclues[i]).to_vec(), "The open clue is not equal to the clue");
            
            let answer = algoanswer(bottom, (&playerclues[i]).to_vec(), maptypes[j], (&mapprop[j]).to_vec());
            
            let proof = play(&mut csprng, g0, (&pcplayers[i]).to_vec(), scplayers[i], maptypes[j], (&mapprop[j]).to_vec(), answer);
            let b = verify(g0, proof, (&pcplayers[i]).to_vec(), maptypes[j], (&mapprop[j]).to_vec(), answer);
            assert!(b == true, "Verify is false");  
        }
      
    }
        
    #[test]  
    // It tests if the algorithm VerifyGame returns false for an incorrect form of clue.
    fn test2vcc(){
    
        // Generation of properties, clues and map.
        let mut csprng = OsRng;	
        let g0 = RISTRETTO_BASEPOINT_POINT; // generator used in the public key of the player
        let c = typesandproperties(&mut csprng); // random generation of 5 types and 14 properties in a RistrettoPoint
        let t = c.0; // vector of 5 elements
        let p = c.1; // vector of 14 elements
        let bottom = c.2;
	let n = 108; // n is the number of cell.  
        // It generates a random map.
        let map = buildrandommap((&t).to_vec(), (&p).to_vec(), n);
        let maptypes = map.0;
        let mapprop = map.1;
        
        // It generates an random cryptid habitat.
        let between = Uniform::from(0..n);
        let mut rng = rand::thread_rng();
        let j = between.sample(&mut rng); 
    
        let d = 3; // d is the number of players.
        let genplayers = vec![g0; d]; // genplayers is the vector of generators used for the public key of the players.
        let genmaster = g0; // genmaster is the generator used for the public key of the game master.
        
        for i in 0..11{
            let cluesforms = vec![0, 1, i];
 
            // It generates incorrect clues.
            let playerclues = vec![buildclue((&t).to_vec(), (&p).to_vec(), bottom, maptypes[j], (&mapprop[j]).to_vec(), cluesforms[0]), buildclue((&t).to_vec(), (&p).to_vec(), bottom, maptypes[j], (&mapprop[j]).to_vec(), cluesforms[1]), buildincorrectclue((&t).to_vec(), (&p).to_vec(), bottom, maptypes[j], (&mapprop[j]).to_vec(), cluesforms[2])];
        
            let keyc = genplayerclues(& mut csprng, (&genplayers).to_vec(), (&playerclues).to_vec());
            let pcplayers = keyc.0; 
            let scplayers = keyc.1;
            
            let proof = provegame(& mut csprng, (&t).to_vec(), (&p).to_vec(),  bottom, (&maptypes).to_vec(), (&mapprop).to_vec(), j, genmaster, (&genplayers).to_vec(), (&pcplayers).to_vec(), (&scplayers).to_vec());

            let pg = proof.0;
            let proof0 = proof.1;
            let proof1 = proof.2;
            let proof2 = proof.3;
            let proof3 = proof.4;
    
            let b = verifygame((&t).to_vec(), (&p).to_vec(), bottom, (&maptypes).to_vec(), (&mapprop).to_vec(), genmaster, (&genplayers).to_vec(), (&pcplayers).to_vec(), pg, proof0, proof1, proof2, proof3);
            assert!(b != (true, true, true, true), "Verify is true."); 
        
            for i in 0..d{
  
                let open = openclue((&pcplayers[i]).to_vec(), scplayers[i]);
                assert!(open == (&playerclues[i]).to_vec(), "The open clue is not equal to the clue.");
            
                let answer = algoanswer(bottom, (&playerclues[i]).to_vec(), maptypes[j], (&mapprop[j]).to_vec());
                let proof = play(&mut csprng, g0, (&pcplayers[i]).to_vec(), scplayers[i], maptypes[j], (&mapprop[j]).to_vec(), answer);
                let b = verify(g0, proof, (&pcplayers[i]).to_vec(), maptypes[j], (&mapprop[j]).to_vec(), answer);
                assert!(b == true, "Verify is false."); 
            } 
        }
    }
    
    // It builds different incorrect clue:
    pub fn buildincorrectclue(t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>, bottom: RistrettoPoint, tj: RistrettoPoint, pj: Vec<RistrettoPoint>, i: usize) -> Vec<RistrettoPoint>{
        
        let mut csprng = OsRng;	
  
        if i == 0{  
            return vec![tj, tj, bottom];   
        }
        if i == 1{
            return vec![bottom, bottom, RistrettoPoint::identity()];
        }
        if i == 2{
            return vec![RistrettoPoint::identity(),  RistrettoPoint::identity(), bottom];
        }
        if i == 3{
            return vec![tj, bottom, bottom];
        }
        if i == 4{
            return vec![tj, RistrettoPoint::identity(), bottom];
        }
        if i == 5{
            return vec![bottom, bottom, bottom];
        }
        if i == 6{
            let mut typ = random_point(&mut csprng);
            while tj == typ{
                typ = random_point(&mut csprng);
            }
            return vec![tj, typ, bottom];
        }
        if i == 7{
            let mut typ = random_point(&mut csprng);
            while tj == typ{
                typ = random_point(&mut csprng);
            }
            return vec![typ, typ, bottom];
        }
        if i == 8{
            let mut prop = random_point(&mut csprng);
            while pj.contains(&prop){
                prop = random_point(&mut csprng);
            }
            return vec![bottom, bottom, prop];
        }
        if i == 9{
            let mut typ = random_point(&mut csprng);
            while t.contains(&typ){
                typ = random_point(&mut csprng);
            }
            return vec![typ, typ, bottom];
        }
        else{
            let mut prop = random_point(&mut csprng);
            while p.contains(&prop){
                prop = random_point(&mut csprng);
            }
            return vec![bottom, bottom, prop];
        }	
    }
}
