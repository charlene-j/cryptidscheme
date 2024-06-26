use rand_core::{CryptoRng, RngCore};
use rand::{Rng, distributions::{Distribution, Uniform}};
use std::{time::Duration, time::Instant, io, io::Write, fs::File, fs};
use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar, traits::Identity, constants::RISTRETTO_BASEPOINT_POINT};
use curve25519_dalek::ristretto::CompressedRistretto;
use sha256::digest;
use hex::FromHex;
use std::io::Read;
use std::io::IoSlice;


// Definition of structure for the proof.
#[derive(Debug, PartialEq)]
pub enum Proof{

    ProofMaybe{r_0: RistrettoPoint, r_1: Vec<RistrettoPoint>, c_1: Vec<Scalar>, z_0: Scalar, z_1: Vec<Scalar>},
    ProofNo{y_0_p: RistrettoPoint, y_1_p: Vec<RistrettoPoint>, r_0: RistrettoPoint, r_r: Vec<RistrettoPoint>, s_0:  RistrettoPoint, s_s: Vec<RistrettoPoint>, u_u: Scalar, v_v: Scalar},
    Error{err: bool},
}

// It generates a random scalar (given in the curve25519_dalek library).
fn random_scalar<T: CryptoRng + RngCore>(csprng: &mut T) -> Scalar{

    let mut scalar_bytes = [0u8; 32];
    csprng.fill_bytes(&mut scalar_bytes);
    Scalar::from_bytes_mod_order(scalar_bytes)
}
    
// It generates a random RistrettoPoint.
pub fn random_point<T: CryptoRng + RngCore>(csprng: & mut T) -> RistrettoPoint{
    
    let r = random_scalar(csprng);
    let point = r * RISTRETTO_BASEPOINT_POINT;
    return point
}

// It converts a [u8; 32] in Scalar.
fn convert_scalar(a: [u8; 32]) -> Scalar{
    
    let s = Scalar::from_bytes_mod_order(a);
    return s
}	       

// It converts a RistrettoPoint in [u8; 32].
fn convert_ristretto(t: RistrettoPoint) -> [u8; 32]{

    let conv = t.compress();
    let conv2 = conv.to_bytes();
    return conv2
}
  
// ElGamal Encryption/Decryption.
fn gen_elgamal<T: CryptoRng + RngCore>(csprng: &mut T, g: RistrettoPoint) -> (RistrettoPoint, RistrettoPoint, Scalar){
    
    let sk = random_scalar(csprng);
    let pk = sk * g;
    return (g, pk, sk)
}
	
fn enc_elgamal<T: CryptoRng + RngCore>(csprng: &mut T, g: RistrettoPoint, pk: RistrettoPoint, m: RistrettoPoint)-> (RistrettoPoint, RistrettoPoint){ 
	
    let r = random_scalar(csprng);
    let c1 = r * g;
    let c2 = m + r * pk;
    return (c1, c2)
}
	
fn dec_elgamal(sk: Scalar, c1: RistrettoPoint, c2: RistrettoPoint)-> RistrettoPoint{ 

    let m = c2 - sk * c1 ;
    return m
}
	
// It hashes and concatenates a RistrettoPoint vector.
fn hash_vec(input: Vec<RistrettoPoint>) -> Scalar{
		
    let mut k: Vec<[u8; 32]> = Vec::new();	
    for p in input{
	let p_p = convert_ristretto(p);
	k.push(p_p);
    }
    let conc = k.concat();
    let h = digest(&conc); 
    let v = <[u8; 32]>::from_hex(h);
    let mut u = [0u8; 32];
        
    for j in 0..32{  
        u[j] = v.unwrap()[j];
    }   
    return convert_scalar(u);      
}
 
// It initializes a vector of size t. 
fn init_vec_ristretto(t: usize) -> Vec<RistrettoPoint>{

    let vec = vec![RistrettoPoint::identity(); t];
    return vec
}

fn init_vec_scalar(t: usize) -> Vec<Scalar>{
    
    let vec = vec![convert_scalar([0u8; 32]); t];
    return vec
}
    	   
// Setup of cell, clues, etc.
// Generation of random Ristretto group elements for defining the types and the properties.
pub fn typesandproperties<T: CryptoRng + RngCore>(csprng: &mut T) -> (Vec<RistrettoPoint>, Vec<RistrettoPoint>, RistrettoPoint){
    
    let mut t: Vec<RistrettoPoint> = Vec::new();
    let mut p: Vec<RistrettoPoint> = Vec::new();
    // It generates the bottom element.
    let bottom = random_point(csprng);
	
    // It generates the five types.
    let mut k = 0;
    while k < 5{
        let mut ti = random_point(csprng);
        while ti == bottom || t.contains(&ti){
            ti = random_point(csprng);
        }
        t.push(ti);
        k += 1;
    }
    
    // It generates the fourteen properties.
    k = 0;
    while k < 14{
        let mut pi = random_point(csprng);
        while pi == bottom || t.contains(&pi) || p.contains(&pi) {
            pi = random_point(csprng);
        }
        p.push(pi);
        k += 1;
    }
    return(t, p, bottom)
}

//It generates a specific cell. w gives the index of types and x is the set of index of properties for the cell.
pub fn gencell(t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>, w: usize, mut x: Vec<usize>) -> (RistrettoPoint, Vec<RistrettoPoint>){
    
    let ti = t[w];
    let mut pi: Vec<RistrettoPoint> = Vec::new();
    x.sort();
    let mut k = 0;
    for i in 0..14{
    	if k < x.len(){
    	    if i == x[k]{
        	let px = p[i];
        	pi.push(px);
        	k += 1;
            }
        }
    }
    return(ti, pi)
}

// It generates a random cell. n is the number of properties for the cell.
pub fn randomcell(t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>, n: usize) -> (RistrettoPoint, Vec<RistrettoPoint>){
     
    let between5 = Uniform::from(0..5); 
    let mut rng = rand::thread_rng();  
    let w = between5.sample(&mut rng);
    let mut x:  Vec<usize> = Vec::new();   
    let mut k = 0;
    while k < n{
        let between14 = Uniform::from(0..14); 
        let mut rng = rand::thread_rng();  
        let z = between14.sample(&mut rng);
        if x.contains(&z){
            continue;
        }
        else{
            x.push(z);
        }
        k += 1;    
    }
    let ci = gencell(t, p, w, x);
    return ci
}

// It builds a clue:
// We build two random clues for which the player answer "maybe" for the jth cell.
// i = 0 corresponds to a clue of the form (Tj, Tk, bottom) or (Tk, Tj, bottom) where Tj != Tk,
// i = 1 corresponds to a clue of the form (bottom, bottom, P) where P belongs to  Pj,
// and we build two second other forms of clue for which the player answer "no" for the jth cell. 
// i = 2 corresponds to (Ti, Tk, bottom) where Ti != Tj and Tk != Tj,
// i = 3 corresponds to (bottom, bottom, P) where P does not belong to Pj.
pub fn buildclue(t: Vec<RistrettoPoint>, p: Vec<RistrettoPoint>, bottom: RistrettoPoint, tj: RistrettoPoint, pj:  Vec<RistrettoPoint>, i: usize) -> Vec<RistrettoPoint>{
    
    if i == 0{
        let between5 = Uniform::from(0..5); 
        let mut rng = rand::thread_rng();  
        let mut r1 = between5.sample(&mut rng);
        while t[r1] == tj{
    	    r1 = between5.sample(&mut rng);  
        }
        let r = rng.gen_bool(0.5);
        if r == true{
            return vec![tj, t[r1], bottom];
        }
        else{
            return vec![t[r1], tj, bottom];
        }
    }
    if i == 1{
        let betweenpj = Uniform::from(0..pj.len()); 
        let mut rng = rand::thread_rng();  
        let mut r2 = betweenpj.sample(&mut rng);
        while pj[r2] == RistrettoPoint::identity(){
             r2 = betweenpj.sample(&mut rng);
        }
        return vec![bottom, bottom, pj[r2]];
    }    
    if i == 2{
    	let between5 = Uniform::from(0..5); 
        let mut rng = rand::thread_rng();  
        let mut r3 = between5.sample(&mut rng);
        let mut r4 = between5.sample(&mut rng);

    	while t[r3] == tj || t[r4] == tj || t[r3] == t[r4]{
            r3 = between5.sample(&mut rng);
    	    r4 = between5.sample(&mut rng);
    	}
    	return vec![t[r3], t[r4], bottom];
    }
    else{
        let between14 = Uniform::from(0..14); 
        let mut rng = rand::thread_rng();  
        let mut r5 = between14.sample(&mut rng);
    	while pj.contains(&p[r5]){
    	    r5 = between14.sample(&mut rng);
   	}
   	return vec![bottom, bottom, p[r5]];
    }
}

// It measures the running time of the algorithms GenClue, OpenClue, Play, Verify, and it measures the size of the public clue key and the proof for the scheme CC2.
pub fn measurementscc2<T: CryptoRng + RngCore>(csprng: &mut T, g0: RistrettoPoint, iter: u32){
    
     println!("Average running time of the algorithms GenClue, OpenClue, Play and Verify, and average size of the public clue key and the proof, calculated over {:?} iterations.\n", iter);   
    println!("Execution in progress...\n(The process may take a long time.)\n");
    
    let mut sumgenclue = vec![Duration::ZERO; 4];
    let mut sumopenclue = vec![Duration::ZERO; 4];
    let mut sumplay = vec![Duration::ZERO; 4];
    let mut sumverify = vec![Duration::ZERO; 4];
    
    let mut averagegen = vec![Duration::ZERO; 4];
    let mut averageopen = vec![Duration::ZERO; 4];
    let mut averageplay = vec![Duration::ZERO; 4];
    let mut averageverify = vec![Duration::ZERO; 4];
    
    let mut pcsize = vec![0, 0, 0, 0];
    let mut proofsize = vec![0, 0, 0, 0];
    
    let mut averagepcsize = vec![0, 0, 0, 0];
    let mut averageproofsize = vec![0, 0, 0, 0];
    
    let vecstr = ["(Tj, Tk, bottom)", "(bottom, bottom, P) where P belongs to Pj", "(Tl, Tk, bottom) where Tl != Tj and Tk != Tj", "(bottom, bottom, P) where P does not belong to Pj"];
  
    for _j in 0..iter{
    	
    	// It defines a random map.
    	let maps = typesandproperties(csprng); // Random generation of five types and fourteen properties in a RistrettoPoint.
    	let t = maps.0; // Vector of five elements.
    	let p = maps.1; // Vector of fourteen elements.
    	let bottom = maps.2;
    	
        // It defines a random cell with fourteen properties. For our performance measurement, we maximize the number of properties, this maximizes the computation time and the proof size.
        let cj = randomcell((&t).to_vec(), (&p).to_vec(), 14);
        let tj = cj.0;
        let pj = cj.1;
        
        // For our performance measurement, we need to build a clue of the form (bottom, bottom, P) with P does not belong to Pj, for an answer "no", then we remove a property from the set of properties for the jth cell.
        let mut pjremove = pj.clone();
        pjremove.remove(pj.len()-1);
        
    	// It defines four different forms of clue. 
        let clue0 = buildclue((&t).to_vec(), (&p).to_vec(), bottom, tj, (&pj).to_vec(), 0);
        let clue1 = buildclue((&t).to_vec(), (&p).to_vec(), bottom, tj, (&pj).to_vec(), 1);
        let clue2 = buildclue((&t).to_vec(), (&p).to_vec(), bottom, tj, (&pj).to_vec(), 2);
        let clue3 = buildclue((&t).to_vec(), (&p).to_vec(), bottom, tj, (&pjremove).to_vec(), 3);
        let playerclues = vec![(&clue0).to_vec(), (&clue1).to_vec(), (&clue2).to_vec(), (&clue3).to_vec()];      
    
    	for i in 0..4{
    
    	    let startgen = Instant::now();
            let keyc = genclue(csprng, g0, (&playerclues[i]).to_vec()); 
	    let gentime = startgen.elapsed();
	    sumgenclue[i] += gentime; 
	    
	    let pc = keyc.0; 
    	    let sc = keyc.1;
    	    let _ = wexport((&pc).to_vec());
            let newpc = rexport();
            assert!(newpc == pc, "The pc in the file in not equal to the real pc");
    	    let pcdata = fs::metadata("pc.txt");
    	    pcsize[i] += pcdata.expect("REASON").len();
    	    
    	    let startopenclue = Instant::now();
    	    let open = openclue((&pc).to_vec(), sc);
    	    let opencluetime = startopenclue.elapsed();
    	    assert!(open == (&playerclues[i]).to_vec(), "The open clue is not equal to the clue.");
    	    sumopenclue[i] += opencluetime;
    	    let mut answer = 2;
    	    if i == 0 || i == 1 || i == 2{
    	        if i == 0 || i == 1 {
    	            answer = 1;
    	            assert!(answer == algoanswer(bottom, (&playerclues[i]).to_vec(), tj, (&pj).to_vec()), "The answer is not correct.");
    	        }
    	        if i == 2{
    	            answer = 0;
    	            assert!(answer == algoanswer(bottom, (&playerclues[i]).to_vec(), tj, (&pj).to_vec()), "The answer is not correct.");
    	        } 
                let startplay = Instant::now();
                let proof = play(csprng, g0, (&pc).to_vec(), sc, tj, (&pj).to_vec(), answer);
                let playtime = startplay.elapsed();
                sumplay[i] += playtime;
                let _ = wexportproof(&proof);
                let newproof = rexportproof(answer, pj.clone());
                assert!(newproof == proof, "The proof in the file is not equal to the real proof");
    	        let proofdata = fs::metadata("proof.txt");
    	        proofsize[i] += proofdata.expect("REASON").len();
        
                let startverify = Instant::now();
                let b = verify(g0, proof, (&pc).to_vec(), tj, (&pj).to_vec(), answer);
                assert!(b == true, "Verify is false.");
                println!("Answer is {:?} and Verify is {:?}.", answer, b == true);
                let verifytime = startverify.elapsed(); 
                sumverify[i] += verifytime;    
            }
            else{
    	        let answer = 0;
                assert!(answer == algoanswer(bottom, (&playerclues[i]).to_vec(), tj, (&pjremove).to_vec()), "The answer is not correct.");
                let startplay = Instant::now();
                let proof = play(csprng, g0, (&pc).to_vec(),sc,tj,(&pjremove).to_vec(),answer);
                let playtime = startplay.elapsed();
                sumplay[i] += playtime;
                let _ = wexportproof(&proof);
                let newproof = rexportproof(answer, pjremove.clone());
    	        let proofdata = fs::metadata("proof.txt");
    	        assert!(newproof == proof, "The proof in the file is not equal to the real proof");
    	        proofsize[i] += proofdata.expect("REASON").len();
        
                let startverify = Instant::now();
                let b = verify(g0, proof, (&pc).to_vec(), tj, (&pjremove).to_vec(), answer);
                assert!(b == true, "Verify is false");
                println!("Answer is {:?} and Verify is {:?}.", answer, b == true);
                let verifytime = startverify.elapsed(); 
                sumverify[i] += verifytime;          
            } 
        }        
    }  
    for i in 0..4{
    
    	averagegen[i] = sumgenclue[i]/iter;
    	averageopen[i] = sumopenclue[i]/iter;
    	averageplay[i] = sumplay[i]/iter;
    	averageverify[i] = sumverify[i]/iter;
    	
    	averagepcsize[i] = pcsize[i]/u64::from(iter);
    	averageproofsize[i] = proofsize[i]/u64::from(iter);
        print!("\n");
        if i == 0 || i == 1{
            println!("Answer: maybe");
        }
        else{
            println!("Answer: no");
        }
          
    	println!("Clue of form: {} \nGenClue: {:?}, \nOpenClue: {:?}, \nPlay: {:?}, \nVerify: {:?}, \nSize of public clue key: {:?} bytes, \nSize of proof {:?} bytes.\n", vecstr[i], averagegen[i], averageopen[i], averageplay[i], averageverify[i], averagepcsize[i], averageproofsize[i]);
    } 
} 
  
// It write the public clue in a file.
fn wexport(pc: Vec<RistrettoPoint>) -> io::Result<()>{
    let mut vecpc : Vec<[u8;32]> = Vec::new();
    for i in 0..pc.len(){
    	vecpc.push((pc[i].compress()).to_bytes())
    
    }
    let mut file = File::options().write(true).truncate(true).create(true).open("pc.txt")?;
    for i in 0..vecpc.len(){
    	file.write_vectored(&[IoSlice::new(&vecpc[i])])?;
    }
    return Ok(())
}

// It read the public clue located in a file.
fn rexport() -> Vec<RistrettoPoint>{
    let mut buffer = Vec::new();
    let file = File::open("pc.txt"); 
    let _ = file.expect("REASON").read_to_end(&mut buffer); 
    let mut vecpc : Vec<[u8;32]> = Vec::new();
    let mut array = [0u8;32];
    for i in 0..buffer.len(){
    	array[i%32] = buffer[i];
    	
    	if i % 32 == 31 && i>0{
    		vecpc.push(array.clone());
    	}
    }
    let mut pc : Vec<RistrettoPoint> = Vec::new();
    for i in 0..vecpc.len(){
    	pc.push(CompressedRistretto(vecpc[i]).decompress().unwrap());
    }
    return pc;   
}	

// It write the proof in a file.
fn wexportproof(p: &Proof) -> io::Result<()>{
    let mut vecproof : Vec<[u8;32]> = Vec::new();
    let mut file = File::options().write(true).truncate(true).create(true).open("proof.txt")?;
    match p{
    	Proof::ProofMaybe{r_0, r_1, c_1, z_0, z_1} =>{
    	    vecproof.push(((r_0).compress()).to_bytes());
    	    for i in 0..r_1.len(){
    	    	vecproof.push(((r_1[i]).compress()).to_bytes());	
    	    }
    	    for i in 0..c_1.len(){
    	    	vecproof.push((c_1[i]).to_bytes());
    	    }
    	    vecproof.push((z_0).to_bytes());
    	    for i in 0..z_1.len(){
    	    	vecproof.push((z_1[i]).to_bytes());
    	    }
    	},
    	Proof::ProofNo{y_0_p, y_1_p, r_0, r_r, s_0, s_s, u_u, v_v} =>{ 
    	    vecproof.push(((y_0_p).compress()).to_bytes());
    	    for i in 0..y_1_p.len(){
    	    	vecproof.push(((y_1_p[i]).compress()).to_bytes());	
    	    }
    	    vecproof.push(((r_0).compress()).to_bytes());
    	    for i in 0..r_r.len(){
    	    	vecproof.push(((r_r[i]).compress()).to_bytes());	
    	    }
    	    vecproof.push(((s_0).compress()).to_bytes());
    	    for i in 0..s_s.len(){
    	    	vecproof.push(((s_s[i]).compress()).to_bytes());	
    	    }
    	    vecproof.push((u_u).to_bytes());  
    	    vecproof.push((v_v).to_bytes()); 
    	},
    	&Proof::Error { .. } => todo!(),	
    }
    for i in 0..vecproof.len(){
        file.write_vectored(&[IoSlice::new(&vecproof[i])])?;
    }
    return Ok(())
}

// It read the proof located in a file.
fn rexportproof(answer: usize, pj: Vec<RistrettoPoint>) -> Proof{
    let len = pj.len()+2;
    let mut buffer = Vec::new();
    let file = File::open("proof.txt"); 
    let _ = file.expect("REASON").read_to_end(&mut buffer); 
    let mut vecp : Vec<[u8;32]> = Vec::new();
    let mut array = [0u8;32];
    for i in 0..buffer.len(){
    	array[i%32] = buffer[i];
    	
    	if i % 32 == 31 && i>0{
    		vecp.push(array.clone());
    	}
    }
    if answer == 1{
    	let mut r1 : Vec<RistrettoPoint> = Vec::new();
    	let mut c1 : Vec<Scalar> = Vec::new();
    	let mut z1 : Vec<Scalar> = Vec::new();
    	let r0 = CompressedRistretto(vecp[0]).decompress().unwrap();
        for i in 1..len+1{
            r1.push(CompressedRistretto(vecp[i]).decompress().unwrap());
        }
        for i in len+1..2*len+1{
            c1.push(Scalar::from_bytes_mod_order(vecp[i]));
        }
        let z0 = Scalar::from_bytes_mod_order(vecp[2*len+1]);
        for i in 2*len+2..3*len+2{
            z1.push(Scalar::from_bytes_mod_order(vecp[i]));
        }
        return Proof::ProofMaybe{r_0: r0, r_1: r1, c_1: c1, z_0: z0, z_1: z1}; 
    }
    
    if answer == 0{
    	let mut y1_p : Vec<RistrettoPoint> = Vec::new();
    	let mut rr : Vec<RistrettoPoint> = Vec::new();
    	let mut ss : Vec<RistrettoPoint> = Vec::new();
    	let y0_p = CompressedRistretto(vecp[0]).decompress().unwrap();
        for i in 1..len+1{
            y1_p.push(CompressedRistretto(vecp[i]).decompress().unwrap());
        }
        let r0 = CompressedRistretto(vecp[len+1]).decompress().unwrap();
        for i in len+2..2*len+2{
            rr.push(CompressedRistretto(vecp[i]).decompress().unwrap());
        }
        let s0 = CompressedRistretto(vecp[2*len+2]).decompress().unwrap();
        for i in 2*len+3..3*len+3{
            ss.push(CompressedRistretto(vecp[i]).decompress().unwrap());
        }
        let uu = Scalar::from_bytes_mod_order(vecp[3*len+3]);
        let vv = Scalar::from_bytes_mod_order(vecp[3*len+4]);
        return Proof::ProofNo{y_0_p: y0_p, y_1_p: y1_p, r_0: r0, r_r: rr, s_0: s0, s_s: ss, u_u: uu, v_v: vv}; 
    }
    
    return Proof::Error{err: false};      
}

// Algorithms for the CC2 scheme:
// Algorithm GenClue. g0 is the generator used to generate the player public key.
pub fn genclue <T: CryptoRng + RngCore>(csprng: &mut T, g0: RistrettoPoint, clue: Vec<RistrettoPoint>) -> (Vec<RistrettoPoint>, Scalar){

    let key = gen_elgamal(csprng, g0); // key.0 = g, key.1 = pk and key.2 = sk.
    let mut pc: Vec<RistrettoPoint> = Vec::new();
    pc.push(key.1);
    for c in clue{
        let e = enc_elgamal(csprng, g0, pc[0], c);
	pc.push(e.0); // c1
	pc.push(e.1); // c2	
    }
    return (pc, key.2)
}  

// Algorithm OpenClue.
pub fn openclue(pc: Vec<RistrettoPoint>, sc: Scalar) -> Vec<RistrettoPoint>{
    
    let mut clue: Vec<RistrettoPoint> = Vec::new();
    let mut k = 1;
    while k < pc.len(){
        let c = dec_elgamal(sc, pc[k], pc[k + 1]);
        clue.push(c); 
        k += 2;  
    } 
    return clue
}

pub fn algoanswer(bottom: RistrettoPoint, clue: Vec<RistrettoPoint>, tj: RistrettoPoint, pj: Vec<RistrettoPoint>) -> usize{
    
    if clue[2] == bottom{
        if clue[0] == tj || clue[1] == tj{ 
            return 1
        }
        else{
            return 0
        }
    }
    if clue[0] == bottom && clue[1] == bottom{
        for prop in pj{
            if clue[2] == prop{
                return 1
            }       
        }
        return 0
    }
    assert!(false, "Please give a correct answer.");
    return 2
}

// Prove Play "maybe": it generates the zero knowledge proof when the answer of the player is "maybe".
// We note c1 the first element of the ciphertext and c2 the second element of the ciphertext.
// y0 is the public key pk of the player, y is the vector of all "c2-Tj" (or resp. "c2-P") s.t. Dec_sk((c1, c2)) = Tj (or resp. Dec_sk((c1, c2)) = P belongs to Pj), g0 is the generator used to generate the public key of the player, g is the vector of all "c1", x is the secret key sk. (we prove also that y0 = sk * g0).
fn prove_play_maybe<T: CryptoRng + RngCore>(csprng: &mut T, y0: RistrettoPoint, y: Vec<RistrettoPoint>, g0:  RistrettoPoint, g: Vec<RistrettoPoint>, x: Scalar) -> Proof{

    if y.len() != g.len(){
    	println!("Please give correct values.");
    	return  Proof::Error{err: false};
    }
   
    // It find the index w s.t. y[w] = x * g[w].
    let mut k = 0;
    while k < y.len() &&  y[k] != x * g[k]{
        k += 1;
    }
    let mut w = k;
    if w == y.len(){
        w -= 1;
    }
   
    // Commit:
    let mut r = init_vec_ristretto(y.len()); // r is the vector of commit.  
    let rr = random_scalar(csprng); // It picks a random scalar.
    let rrr = random_scalar(csprng); // It picks another random scalar. 
    let r0 = rr * g0; 
    r[w] = rrr * g[w];

    // Simulation for all instances y[i] != x * g[i].
    let mut c = init_vec_scalar(y.len()); // c[i] is the challenge.
    let mut z = init_vec_scalar(y.len()); // z[i] is the response.
    
    let respsim = simul_maybe(csprng, (&y).to_vec(), (&g).to_vec(), (&r).to_vec(), (&c).to_vec(), (&z).to_vec(), w);   
    r = respsim.0; 
    c = respsim.1; 
    z = respsim.2;

    // Challenge:  
    let mut conc: Vec<RistrettoPoint> = Vec::new(); // It builds the vector to concatenate and hash.    
    conc.push(r0);
    conc.extend((&r).to_vec());
    conc.push(y0);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.extend((&g).to_vec());
    let cc = hash_vec(conc); // cc is the sum of all c[i] where i belongs to {0, ..., y.len()-1}.
    let mut sum = convert_scalar([0u8; 32]);
    for chall in &c{
        sum += chall;
    }
    c[w] = cc - sum;
    
    // Response:
    let z0 = rr + cc * x;
    z[w] = rrr + c[w] * x;

    return Proof::ProofMaybe{r_0: r0, r_1: r, c_1: c, z_0: z0, z_1: z};
}

// Simulator for all instances y[i] != x * g[i]. 
fn simul_maybe<T: CryptoRng + RngCore>(csprng: &mut T, y: Vec<RistrettoPoint>, g: Vec<RistrettoPoint>, mut r:  Vec<RistrettoPoint>, mut c: Vec<Scalar>, mut z: Vec<Scalar>, w: usize) -> (Vec<RistrettoPoint>, Vec<Scalar>, Vec<Scalar>){
    
    for k in 0..y.len(){
        if k != w {
            c[k] = random_scalar(csprng);
            z[k] = random_scalar(csprng);
            r[k] = z[k] * g[k] - c[k] * y[k];   
        }
    }
    return(r, c, z)
}

// Verify the proof when the answer is "maybe".
fn verify_play_maybe(y0: RistrettoPoint, y: Vec<RistrettoPoint>, g0: RistrettoPoint, g: Vec<RistrettoPoint>, r0:  RistrettoPoint, r: Vec<RistrettoPoint>, c: Vec<Scalar>, z0: Scalar, z: Vec<Scalar>) -> bool{
	
    // It computes the challenge with the given values.
    let mut conc: Vec<RistrettoPoint> = Vec::new();     
    conc.push(r0);
    conc.extend((&r).to_vec());
    conc.push(y0);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.extend((&g).to_vec());
    let cc = hash_vec(conc);
    let mut sum = convert_scalar([0u8;32]);
    for chall in &c{
        sum += chall;
    }
    
    // It verifies if the computed challenge is the sum of challenge and z[i] * g[i] = r[i] + c[i] * y[i], for all i belongs to {0, ..., y.len()-1}.
    if cc == sum && z0 * g0 == r0 + cc * y0{
    	for i in 0..y.len(){
    	    if z[i] * g[i] != r[i] + c[i] * y[i]{
        	return false;  
            }
        }
        return true;
    }
    else{
        return false;      
    }    
}

// Prove Play "no": it generates the zero knowledge proof when the answer of the player is "no".
fn prove_play_no<T: CryptoRng + RngCore>(csprng: &mut T, y0: RistrettoPoint, y: Vec<RistrettoPoint>, g0:  RistrettoPoint, g: Vec<RistrettoPoint>, x: Scalar) -> Proof{

    if y.len() != g.len(){
    	println!("Please give correct values.");
    	return  Proof::Error{err: false};
    }

    let bb = random_scalar(csprng);
    let aa = x*bb;
	
    // Commit: 
    let rr = random_scalar(csprng);
    let ss = random_scalar(csprng);    
    let mut r: Vec<RistrettoPoint> = Vec::new(); 
    let r0 = rr * g0;
    for gg in &g{
        r.push(rr * gg);
    }
    let mut h: Vec<RistrettoPoint> = Vec::new(); 
    let h0 = -y0;
    for yy in &y{
        h.push(-yy);
    }
    let mut s: Vec<RistrettoPoint> = Vec::new(); 
    let s0 = ss * h0;
    for hh in &h{
        s.push(ss * hh);
    }
    let y0_p = aa * g0 + bb * h0;	
    let mut y_p: Vec<RistrettoPoint> = Vec::new();
    for k in 0..g.len(){
	y_p.push(aa * g[k] + bb * h[k]);
    }
    
    // Challenge:
    let mut conc: Vec<RistrettoPoint> = Vec::new(); 
    conc.push(r0);
    conc.extend((&r).to_vec());
    conc.push(s0);   
    conc.extend((&s).to_vec());
    conc.push(y0);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.extend((&g).to_vec());
    conc.push(h0);
    conc.extend((&h).to_vec());
    conc.push(y0_p);
    conc.extend((&y_p).to_vec());
    let cc = hash_vec(conc);
    
    // Response:
    let uu = rr + cc * aa;
    let vv = ss + cc * bb;
    
    return Proof::ProofNo{y_0_p: y0_p, y_1_p: y_p, r_0: r0, r_r: r, s_0: s0, s_s: s, u_u: uu, v_v: vv}; 	   
}   
  
fn verify_play_no(y0: RistrettoPoint, y: Vec<RistrettoPoint>, g0: RistrettoPoint, g: Vec<RistrettoPoint>, h0:  RistrettoPoint, h: Vec<RistrettoPoint>, y0_p: RistrettoPoint, y_p: Vec<RistrettoPoint>, r0: RistrettoPoint, r:  Vec<RistrettoPoint>, s0: RistrettoPoint, s: Vec<RistrettoPoint>, uu: Scalar, vv: Scalar) -> bool{

    // It computes the challenge with the given values.
    let mut conc: Vec<RistrettoPoint> = Vec::new(); 
    conc.push(r0);
    conc.extend((&r).to_vec());
    conc.push(s0);
    conc.extend((&s).to_vec());
    conc.push(y0);
    conc.extend((&y).to_vec());
    conc.push(g0);
    conc.extend((&g).to_vec());
    conc.push(h0);
    conc.extend((&h).to_vec());
    conc.push(y0_p);
    conc.extend((&y_p).to_vec());
    
    let cc = hash_vec(conc);
    
    if y0_p == RistrettoPoint::identity() && uu * g0 + vv * h0 == r0 + s0 + cc * y0_p{ // y0_p must be equal to identity.
    	for k in 0..y_p.len(){
            if y_p[k] == RistrettoPoint::identity(){ // For all k belongs to {0, ..., y_p.len()-1}, y_p[k] must not be equal to identity.
                return false;
            }
            else{
                if uu * g[k] + vv * h[k] != r[k] + s[k] + cc * y_p[k]{
                    return false;
                }
            }
        }
    }
    else{
    	return false;
    } 
    return true;       
}

// Algorithm Play. g0 is the generator used to build the public clue key of the player, pc is the public clue key, sc is the secret clue key of the player, (Tj, Pj) is the cell j, answer is the response given by the player for the cell j.
pub fn play<T: CryptoRng + RngCore>(csprng: &mut T, g0: RistrettoPoint, pc: Vec<RistrettoPoint>, sc: Scalar, tj: RistrettoPoint, pj: Vec<RistrettoPoint>, answer: usize)-> Proof{

    let y0 = pc[0];
    let mut g: Vec<RistrettoPoint> = Vec::new();
    let mut y: Vec<RistrettoPoint> = Vec::new();
    g.push(pc[1]);
    g.push(pc[3]);
    y.push(pc[2] - tj);
    y.push(pc[4] - tj);
	
    for i in 0..pj.len(){
        g.push(pc[5]);
	y.push(pc[6] - pj[i]);
    }
	
    if answer == 1{ // answer is maybe.
        return prove_play_maybe(csprng, y0, y, g0, g, sc);  
    }
    if answer == 0{ // answer is no.
    	return prove_play_no(csprng, y0, y, g0, g, sc);
    }
    else{
	println!("Please give a correct answer.");
	return Proof::Error{err: false};
    }	
}

// Algorithm Verify.
pub fn verify(g0: RistrettoPoint, proof: Proof, pc: Vec<RistrettoPoint>, tj: RistrettoPoint, pj: Vec<RistrettoPoint>, answer: usize) -> bool{	
    
    let mut b = false;
    let y0 = pc[0];
    let mut g: Vec<RistrettoPoint> = Vec::new();
    let mut y: Vec<RistrettoPoint> = Vec::new(); 
    g.push(pc[1]);
    g.push(pc[3]);
    y.push(pc[2] - tj);
    y.push(pc[4] - tj);
	
    for i in 0..pj.len(){
        g.push(pc[5]);
	y.push(pc[6] - pj[i]);
    }
		
    match proof{
    	Proof::ProofMaybe{r_0, r_1, c_1, z_0, z_1} =>{ 
    	    if answer == 1{
    		b = verify_play_maybe(y0, y, g0, g, r_0, r_1, c_1, z_0, z_1); 
    	    }
    	},
    	Proof::ProofNo{y_0_p, y_1_p, r_0, r_r, s_0, s_s, u_u, v_v} =>{ 
    	    let mut h: Vec<RistrettoPoint> = Vec::new(); 
            let h0 = -y0;
            for yy in &y{
                h.push(-yy);
            }
    	    if answer == 0{
    		b = verify_play_no(y0, y, g0, g, h0, h, y_0_p, y_1_p, r_0, r_r, s_0 , s_s, u_u, v_v);
    	    }
    	},
    	Proof::Error{err} =>{   	
   	    if answer != 0 || answer != 1{
   		assert!(false, "Please give a correct answer.");
   		b = err;
   	    }
    	},
    }
    return b  
}
