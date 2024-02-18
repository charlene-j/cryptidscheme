use cryptocryptid::{typesandproperties, buildrandommap, schemecc2, funanswer, provegame, verifygame}; //gencell};
use cryptocryptid::{buildcluesplayers, buildclueskeys}; //gencell};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use rand_core::{OsRng};
use rand::distributions::Uniform;
use rand::distributions::Distribution;
use std::time::Instant;


//https://ristretto.group/why_ristretto.html
//https://datatracker.ietf.org/meeting/109/materials/slides-109-cfrg-ristrettodecaf-00


fn main(){ //-> std::io::Result<(),io::Error> {
    
    // Setup of properties and map
    let g0 = RISTRETTO_BASEPOINT_POINT; // generator used in the public key of the player
    let mut csprng = OsRng;	
    let maps = typesandproperties(&mut csprng); // random generation of 5 types and 14 properties in a RistrettoPoint
    let t = maps.0; // vector of 5 elements
    let p = maps.1; // vector of 14 elements
	
    // Defines one specific cell
    //let prop = vec![0,1,2,3,4,5,6,7,8,9,10,11,13]; // prop correspond to the cell with the properties prop
    //let cj = gencell((&t).to_vec(),(&p).to_vec(),id,4,prop); // we built a cell with the type 4 and the properties prop
    //let tj = cj.0; 
    //let pj = cj.1;
    
    let n = 108;
    
    //Generates a random map
    let map = buildrandommap((&t).to_vec(),(&p).to_vec(),n);
    let maptypes = map.0;
    let mapprop = map.1;
    
    //Generates an random cryptid habitat
    let betweenn = Uniform::from(0..n);
    let mut rngn = rand::thread_rng();
    let j = betweenn.sample(&mut rngn); // cryptid habitat
    
    let d = 4; // number of players
    let genplayers = vec![g0;d];
    let genmaster = g0;
    let cluesforms = vec![0,1,1,0]; // to forms of clues
    
    // Generates random clues according to the cryptid habitat
    let cluesplayers = buildcluesplayers((&t).to_vec(),(&p).to_vec(),maptypes[j],(&mapprop[j]).to_vec(),(&cluesforms).to_vec());
    let keyc = buildclueskeys(& mut csprng, (&genplayers).to_vec(), (&cluesplayers).to_vec());
    let pcplayers = keyc.0; // pas oublier que cc2 les genère
    let scplayers = keyc.1;
    
    //let master = buildmaster(& mut csprng, genmaster, tj, (&pj).to_vec()); // pk = master.0, sk = master.1
    let a = 1;
    let answer = funanswer((&cluesplayers[a]).to_vec(), maptypes[j], (&mapprop[j]).to_vec());
    schemecc2(& mut csprng, genplayers[a], (&cluesplayers[a]).to_vec(), maptypes[j], (&mapprop[j]).to_vec(), answer);
    
    let startprovegame = Instant::now();
    let proof = provegame(& mut csprng,(&t).to_vec(), (&p).to_vec(), (&maptypes).to_vec(), (&mapprop).to_vec(),j, genmaster, (&genplayers).to_vec(), (&pcplayers).to_vec(), (&scplayers).to_vec());
    let provegametime = startprovegame.elapsed();
    println!("provegame took {:?}", provegametime);
    
    let pg = proof.0;
    let proof0 = proof.1;
    let proof1 = proof.2;
    let proof2 = proof.3;
    let proof3 = proof.4;
    
    let startverifygame = Instant::now();
    let b = verifygame((&t).to_vec(), (&p).to_vec(), (&maptypes).to_vec(), (&mapprop).to_vec(),genmaster, (&genplayers).to_vec(), (&pcplayers).to_vec(),pg,proof0,proof1,proof2,proof3);
    let verifygametime = startverifygame.elapsed();
    println!("verifygame took {:?}", verifygametime);
    println!("proofgame {:?}",b);
    				
}
